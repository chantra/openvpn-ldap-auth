/*
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 * 
 * ldap-auth.c
 * OpenVPN LDAP authentication plugin
 *
 *  Copyright (C) 2009 Emmanuel Bretelle <chantra@debuntu.org>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *  USA.
 */


#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>

#include <openvpn/openvpn-plugin.h>
#include <errno.h>
#include <ldap.h>

#include <pthread.h>


#include "config.h"
#include "cnf.h"
#include "utils.h"
#include "debug.h"
#include "action.h"
#include "list.h"
#include "la_ldap.h"
#include "client_context.h"
#include "ldap_profile.h"

#define DODEBUG(verb) ((verb) >= 4)

pthread_mutex_t    action_mutex;
pthread_cond_t     action_cond;
pthread_attr_t     action_thread_attr;
pthread_t          action_thread = 0;

/* forward declaration of main loop */
static void *action_thread_main_loop (void *c);

void
action_push( list_t *list, action_t *action)
{
  pthread_mutex_lock( &action_mutex );
  if( action->type == LDAP_AUTH_ACTION_QUIT )
    list_prepend( list, ( void * )action );
  else
    list_append( list, ( void * )action ); 
  if( list_length( list ) == 1 ){
    pthread_cond_signal( &action_cond );
    LOGINFO( "Sent signal to authenticating loop\n" );
  }
  pthread_mutex_unlock( &action_mutex );
}

action_t *
action_pop (list_t *l){
  action_t *a = NULL;
  pthread_mutex_lock (&action_mutex);
  if (list_length (l) == 0){
    pthread_cond_wait (&action_cond, &action_mutex);
  }
  /* get the action item */
  a = list_remove_item_at (l, 0);
  pthread_mutex_unlock (&action_mutex);
  return a;
}


/*
 * Name/Value pairs for conversation function.
 * Special Values:
 *
 *  "USERNAME" -- substitute client-supplied username
 *  "PASSWORD" -- substitute client-specified password
 */

#define N_NAME_VALUE 16

struct name_value {
  const char *name;
  const char *value;
};

struct name_value_list {
  int len;
  struct name_value data[N_NAME_VALUE];
};

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
static const char *
get_env (const char *name, const char *envp[])
{
  if (envp){
    int i;
    const int namelen = strlen (name);
    for (i = 0; envp[i]; ++i){
      if (!strncmp (envp[i], name, namelen))
	    {
	      const char *cp = envp[i] + namelen;
	      if (*cp == '=')
		      return cp + 1;
	    }
	  }
  }
  return NULL;
}

/*
 * Given an environmental variable name, dumps
 * the envp array values.
 */
static void
dump_env (const char *envp[])
{
  
  fprintf (stderr, "//START of dump_env\\\\\n");
  if (envp){
    int i;
    for (i = 0; envp[i]; ++i)
      fprintf (stderr, "%s\n", envp[i]);
  }
  fprintf (stderr, "//END of dump_env\\\\\n");
}


/*
 * Return the length of a string array
 */
static int
string_array_len (const char *array[])
{
  int i = 0;
  if (array){
    while (array[i])
	    ++i;
  }
  return i;
}

#ifdef DO_DAEMONIZE

/*
 * Daemonize if "daemon" env var is true.
 * Preserve stderr across daemonization if
 * "daemon_log_redirect" env var is true.
 */
static void
daemonize (const char *envp[])
{
  const char *daemon_string = get_env ("daemon", envp);
  if (daemon_string && daemon_string[0] == '1')
    {
      const char *log_redirect = get_env ("daemon_log_redirect", envp);
      int fd = -1;
      if (log_redirect && log_redirect[0] == '1')
	fd = dup (2);
      if (daemon (0, 0) < 0)
	{
	  fprintf (stderr, "LDAP-AUTH: daemonization failed\n");
	}
      else if (fd >= 3)
	{
	  dup2 (fd, 2);
	  close (fd);
	}
    }
}

#endif

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v2 (unsigned int *type_mask, const char *argv[], const char *envp[], struct openvpn_plugin_string_list **return_list)
{

  ldap_context_t *context;

  const char *configfile = NULL;
  int rc = 0;

  /*
   * Allocate our context
   */
  context = ldap_context_new( );
  if( !context ){
    LOGERROR( "Failed to initialize context\n" );  
    goto error;
  }
  /*
   * Intercept the --auth-user-pass-verify callback.
   */
  *type_mask = OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

   while ( ( rc = getopt ( string_array_len (argv), (char **)argv, ":H:D:c:b:f:t:WZ" ) ) != - 1 ){
    switch( rc ) {
      case 'H':
        context->config->ldap->uri = strdup(optarg);
        break;
      case 'b':
        context->config->profile->basedn = strdup(optarg);
        break;
      case 'f':
        context->config->profile->search_filter = strdup(optarg);
        break;
      case 'Z':
        context->config->ldap->ssl = strdup("start_tls");
        break;
      case 'D':
        context->config->ldap->binddn = strdup(optarg);
        break;
      case 'W':
        context->config->ldap->bindpw = get_passwd("BindPW Password: ");
        //printdebug( "Password is %s: length: %d\n", config->bindpw, strlen(config->bindpw) );
        break;
      case 'c':
        configfile = optarg;
        break;
      case 't':
        context->config->ldap->timeout = atoi( optarg );
        break;
      case '?':
        fprintf( stderr, "LDAP-AUTH: Unknown Option -%c !!\n", optopt );
        break;
      case ':':
        fprintf( stderr, "LDAP-AUTH: Missing argument for option -%c !!\n", optopt );
        break;
      default:
        fprintf(stderr, "LDAP-AUTH: ?? getopt returned character code 0%o ??\n", rc);
        abort();
    }
  }

  /**
   * Parse configuration file is -c filename is provided
   */ 
  if( configfile ) config_parse_file( configfile, context->config );
  /**
   * Set default config values
   */ 
  config_set_default( context->config );

  /*
   * Get verbosity level from environment
   */
  
#ifdef ENABLE_LDAPUSERCONF
  /* when ldap userconf is define, we need to hook onto those callbacks */
  if( config_is_pf_enabled( context->config )){
    *type_mask |= OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_ENABLE_PF);
  }
  *type_mask |= OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_CLIENT_CONNECT_V2)
                | OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_CLIENT_DISCONNECT);
#endif

  const char *verb_string = get_env ("verb", envp);
  if (verb_string)
    context->verb = atoi (verb_string);

  if( DODEBUG( context->verb ) )
      config_dump( context->config ); 


  /* set up mutex/cond */
  pthread_mutex_init (&action_mutex, NULL);
  pthread_cond_init (&action_cond, NULL);

  /* start our authentication thread */
  pthread_attr_setdetachstate(&action_thread_attr, PTHREAD_CREATE_JOINABLE);
  rc = pthread_create(&action_thread, &action_thread_attr, action_thread_main_loop, context);
  
  switch( rc ){
    case EAGAIN:
      LOGERROR( "pthread_create returned EAGAIN: lacking resources\n" );
      break;
    case EINVAL:
      LOGERROR( "pthread_create returned EINVAL: invalid attributes\n" );
      break;
    case EPERM:
      LOGERROR( "pthread_create returned EPERM: no permission to create thread\n" );
      break;
    case 0:
      break;
    default:
      LOGERROR( "pthread_create returned an unhandled value: %d\n", rc );
  }
  if( rc == 0)
    return (openvpn_plugin_handle_t) context;

  /* Failed to initialize, free resources */
  pthread_attr_destroy( &action_thread_attr );
  pthread_mutex_destroy( &action_mutex );
  pthread_cond_destroy( &action_cond );

error:
  if ( context ){
    ldap_context_free (context);
  }
  return NULL;
}

/* write a value to auth_control_file */
int
write_to_auth_control_file( char *auth_control_file, char value )
{
  int fd, rc;
  fd = open( auth_control_file, O_WRONLY | O_CREAT, 0700 );
  if( fd == -1 ){
    LOGERROR( "Could not open file %s: %s\n", auth_control_file, strerror( errno ) );
    return -1;
  }
  rc = write( fd, &value, 1 );
  if( rc == -1 ){
    LOGERROR( "Could not write value %c to  file %s: %s\n", value, auth_control_file, strerror( errno ) );
  }else if( rc !=1 ){
    LOGERROR( "Could not write value %c to file %s\n", value, auth_control_file );
  }
  rc = close( fd );
  if( rc != 0 ){
    LOGERROR( "Could not close file %s: %s\n", auth_control_file, strerror( errno ) );
  }
  return rc == 0;
}


OPENVPN_EXPORT int
openvpn_plugin_func_v2 (openvpn_plugin_handle_t handle,
                        const int type,
                        const char *argv[],
                        const char *envp[],
                        void *per_client_context,
                        struct openvpn_plugin_string_list **return_list)
{
  ldap_context_t *context = (ldap_context_t *) handle;
  auth_context_t *auth_context = NULL;
  pthread_t tid;
  action_t *action = NULL;

  
  config_t *config = context->config;
  int rc;
  int res = OPENVPN_PLUGIN_FUNC_ERROR;

  if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY){
    /* get username/password/auth_control_file from envp string array */
    const char *username = get_env ("username", envp);
    const char *password = get_env ("password", envp);
    const char *auth_control_file = get_env ( "auth_control_file", envp );
    const char *pf_file = get_env ("pf_file", envp);



    /* required parameters check */
    if (!username){
      LOGERROR("No username supplied to OpenVPN plugin");
      return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    auth_context = auth_context_new( );
    if( !auth_context ){
      LOGERROR( "Could not allocate auth_context before calling thread\n" );
      return res;
    }
    if( username ) auth_context->username = strdup( username );
    if( password ) auth_context->password = strdup( password );
    if( pf_file ) auth_context->pf_file = strdup( pf_file );
    if( auth_control_file ) auth_context->auth_control_file = strdup( auth_control_file );
    /* If some argument were missing or could not be duplicate */
    if( !(auth_context->username && auth_context->password && auth_context->auth_control_file ) ){
      auth_context_free( auth_context );
      return res;
    }
    action = action_new( );
    action->type = LDAP_AUTH_ACTION_AUTH;
    action->context = auth_context;
    action->client_context = per_client_context;
    action->context_free_func = auth_context_free;
    action_push( context->action_list, action );
    return OPENVPN_PLUGIN_FUNC_DEFERRED;
    
  }
#ifdef ENABLE_LDAPUSERCONF
  else if (type == OPENVPN_PLUGIN_ENABLE_PF){
    /* unfortunately, at this stage we dont know anything about the client
     * yet. Let assume it is enabled, we will define default somewhere
     */
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
  }else if( type == OPENVPN_PLUGIN_CLIENT_CONNECT_V2 ){
    /* on client connect, we return conf options through return list
     */
    client_context_t *cc = per_client_context;
    ldap_account_t *a = cc->ldap_account;
    char *ccd_options = ldap_account_get_options_to_string( cc->ldap_account );
    if( ccd_options ){
      *return_list = la_malloc( sizeof( struct openvpn_plugin_string_list ) );
      if( *return_list != NULL){
        (*return_list)->next = NULL;
        (*return_list)->name = strdup( "config" );
        (*return_list)->value = ccd_options;
      }
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
  }else if( type == OPENVPN_PLUGIN_CLIENT_DISCONNECT ){
    /* nothing done for now
     * potentially, session could be logged
     */
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
  }
#endif
  return res;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
  ldap_context_t *context = (ldap_context_t *) handle;
  action_t *action = action_new( );

  if (DODEBUG (context->verb))
    LOGINFO( "close\n" );
  if( action){
    action->type = LDAP_AUTH_ACTION_QUIT;
    action_push( context->action_list, action );
    if( DODEBUG( context->verb ) )
      LOGINFO ("Waiting for thread to return\n");
    pthread_join( action_thread, NULL );
    if( DODEBUG( context->verb ) )
      LOGINFO ("Thread returned queries left in queue: %d\n", list_length( context->action_list ));
    pthread_attr_destroy( &action_thread_attr );
    pthread_mutex_destroy( &action_mutex );
    pthread_cond_destroy( &action_cond );
  }
  ldap_context_free( context );
  //pthread_exit(NULL);
}

OPENVPN_EXPORT void
openvpn_plugin_abort_v1 (openvpn_plugin_handle_t handle)
{
  ldap_context_t *context = (ldap_context_t *) handle;
  if (context) {
    action_t *action = action_new( );

    if (DODEBUG (context->verb))
      LOGINFO( "close\n" );
    if( action){
      action->type = LDAP_AUTH_ACTION_QUIT;
      action_push( context->action_list, action );
      if( DODEBUG( context->verb ) )
        LOGINFO ("Waiting for thread to return\n");
      pthread_join( action_thread, NULL );
      if( DODEBUG( context->verb ) )
        LOGINFO ("Thread returned queries left in queue: %d\n", list_length( context->action_list ));
      pthread_attr_destroy( &action_thread_attr );
      pthread_mutex_destroy( &action_mutex );
      pthread_cond_destroy( &action_cond );
    }
    ldap_context_free( context );
  }
}

OPENVPN_EXPORT int
openvpn_plugin_select_initialization_point_v1 (void)
{
  return OPENVPN_PLUGIN_INIT_POST_UID_CHANGE;
}

void *
action_thread_main_loop (void *c)
{
  ldap_context_t *context = c;
  action_t *action = NULL;
  int rc;

  int loop = 1;
  while( loop ){
    action = action_pop(context->action_list);
    /* TODO, do some action */
    if (action){
      switch (action->type){
        case LDAP_AUTH_ACTION_AUTH:
          if( DODEBUG(context->verb ) ){
            LOGINFO( "Authentication requested for user %s\n",
                      ((auth_context_t *)action->context)->username);
          }
          rc = la_ldap_handle_authentication( context, action );
          /* we need to write the result to  auth_control_file */
          if( DODEBUG(context->verb ) ){
            LOGINFO( "User %s: Writing %c to file %s\n",
                          ((auth_context_t *)action->context)->username,
                          rc == OPENVPN_PLUGIN_FUNC_SUCCESS ? '1' : '0',
                          ((auth_context_t *)action->context)->auth_control_file);
          }
          write_to_auth_control_file ( ((auth_context_t *)action->context)->auth_control_file,
                                        rc == OPENVPN_PLUGIN_FUNC_SUCCESS ? '1' : '0');
          break;
        case LDAP_AUTH_ACTION_QUIT:
          if( DODEBUG(context->verb ) ){
            LOGINFO( "Authentication thread received ACTION_QUIT\n");
          }
          loop = 0;
          break;
        default:
          if (DODEBUG (context->verb) ){
            LOGINFO( "Unknown action %d\n", action->type);
          }
      }
      action_free( action );
    }
  }
  pthread_exit (NULL);
}

OPENVPN_EXPORT void *
openvpn_plugin_client_constructor_v1( openvpn_plugin_handle_t handle){
  client_context_t *cc = client_context_new( );
  return (void *)cc;
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1( openvpn_plugin_handle_t handle, void *per_client_context ){
  client_context_t *cc = per_client_context;
  client_context_free( cc );
}
