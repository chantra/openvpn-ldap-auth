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


#include "cnf.h"
#include "utils.h"
#include "debug.h"
#include "action.h"
#include "list.h"

#define DODEBUG(verb) ((verb) >= 4)

pthread_mutex_t    action_mutex;
pthread_cond_t     action_cond;
pthread_attr_t     action_thread_attr;
pthread_t          action_thread;

/* forward declaration of main loop */
static void *action_thread_mail_loop (void *c);
/**
 * Plugin state, used by foreground
 */
typedef struct ldap_context
{

  /* Parsed config info */
  config_t *config;

  /* Verbosity level of OpenVPN */
  int verb;
  /* list of pending action to execute*/
  list_t *action_list;

} ldap_context_t;

/**
 * Data to be passed to a 
 * thread for user authentication
 */
typedef struct auth_context
{
  config_t        *config;
  int             verb;
  char            *username;
  char            *password;
  char            *auth_control_file;
} auth_context_t;

void
action_push( list_t *list, action_t *action)
{
  pthread_mutex_lock( &action_mutex );
  list_append( list, ( void * )action ); 
  if( list_length( list ) == 1 ){
    pthread_cond_signal( &action_cond );
    LOGINFO( "Sent signal to authenticating loop\n" );
  }
  pthread_mutex_unlock( &action_mutex );
}
/** 
 * Allocate Authentication context resources
 */
auth_context_t *
auth_context_new( void ){
  auth_context_t *a = NULL;
  a = la_malloc( sizeof( auth_context_t ) ); 
  if( a ) la_memset( a, 0, sizeof( auth_context_t ) );  
  return a;
}

/**
 * Free Authentication context resources
 */
void
auth_context_free( auth_context_t *a ){
  if( !a ) return;
  if( a->config ) config_free( a->config );
  if( a->username ) free( a->username );
  if( a->password ) free( a->password );
  if( a->auth_control_file ) free( a->auth_control_file );
  free( a );
  return;
}

/**
 * Free LDAP context resources
 */

void
ldap_context_free( ldap_context_t *l ){
  if( !l ) return;
  if( l->config ) config_free( l->config );
  if( l->action_list) list_free( l->action_list, NULL );
  free( l );
}

/**
 * Allocate LDAP context resources
 * return NULL on memory allocation issue
 */
ldap_context_t *
ldap_context_new( void ){
  ldap_context_t *l;
  l = malloc( sizeof( ldap_context_t ) );
  if( !l ) return NULL;
  memset( l, 0, sizeof( ldap_context_t ) );
  l->config = config_new( );
  if( !l->config ){
    ldap_context_free( l );
    return NULL;
  }
  l->action_list = list_new( );
  if( !l->action_list ){
    ldap_context_free( l );
    return NULL;
  }
  return l;
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
openvpn_plugin_open_v1 (unsigned int *type_mask, const char *argv[], const char *envp[])
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
  /* create out pthread_t list */
  /*
  context->lthread = list_new( );
  if( !context->lthread ){
    LOGERROR( "Failed to initialize thread list\n" );
    goto error;
  }
  */
  /*
   * Intercept the --auth-user-pass-verify callback.
   */
  *type_mask = OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

   while ( ( rc = getopt ( string_array_len (argv), (char **)argv, ":H:D:c:b:f:t:WZ" ) ) != - 1 ){
    switch( rc ) {
      case 'H':
        context->config->uri = strdup(optarg);
        break;
      case 'b':
        context->config->basedn = strdup(optarg);
        break;
      case 'f':
        context->config->search_filter = strdup(optarg);
        break;
      case 'Z':
        context->config->ssl = strdup("start_tls");
        break;
      case 'D':
        context->config->binddn = strdup(optarg);
        break;
      case 'W':
        context->config->bindpw = get_passwd("BindPW Password: ");
        //printdebug( "Password is %s: length: %d\n", config->bindpw, strlen(config->bindpw) );
        break;
      case 'c':
        configfile = optarg;
        break;
      case 't':
        context->config->timeout = atoi( optarg );
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
  rc = pthread_create(&action_thread, &action_thread_attr, action_thread_mail_loop, context);
  
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

  pthread_attr_destroy( &action_thread_attr );
  pthread_mutex_destroy( &action_mutex );
  pthread_cond_destroy( &action_cond );

error:
  if ( context ){
    if( context->action_list ){
      /* TODO will most likely need a custom free function */
      list_free( context->action_list, NULL );
    }
    ldap_context_free (context);
  }
  return NULL;
}


/**
 * bind given ldap connection with username and password
 * Anonymous binding is achived by providing NULL username and password
 */

int
ldap_binddn( LDAP *ldap, const char *username, const char *password ){
  int rc;
  struct berval bv, *servcred = NULL;

  if( password && strlen(password) ){
    bv.bv_len = strlen(password);
    bv.bv_val = (char *)password;
  }else{
    bv.bv_len = 0;
    bv.bv_val = NULL;
  }
  rc = ldap_sasl_bind_s( ldap, username, LDAP_SASL_SIMPLE, &bv, NULL, NULL, &servcred);
  if( servcred ) ber_bvfree( servcred );
  return rc;
}

/**
 * Set up a connection to LDAP given the context configuration
 * Do not bind to LDAP, use ldap_bindn for that purpose
 */
LDAP *
connect_ldap( auth_context_t *auth_context ){
  LDAP *ldap;
  int rc;
  config_t *config = auth_context->config;
  int ldap_tls_require_cert;
  struct timeval timeout;

  /* init connection to ldap */
  rc = ldap_initialize(&ldap, config->uri);
  if( rc!= LDAP_SUCCESS ){
    LOGERROR( "ldap_initialize returned (%d) \"%s\" : %s\n", rc, ldap_err2string(rc), strerror(errno) );
    goto connect_ldap_error;
  }
  /* Version */
  rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &(config->ldap_version));
  if( rc != LDAP_OPT_SUCCESS ){
    LOGERROR( "ldap_set_option version %d returned (%d) \"%s\"\n", config->ldap_version, rc, ldap_err2string(rc) );
    goto connect_ldap_error;
  }
  /* Timeout */
  timeout.tv_sec = config->timeout;
  timeout.tv_usec = 0;
  rc = ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout );
  if( rc != LDAP_OPT_SUCCESS ){
    LOGERROR( "ldap_set_option timeout %ds returned (%d) \"%s\"\n", config->timeout, rc, ldap_err2string(rc) );
    goto connect_ldap_error;
  }
  /* SSL/TLS */
  if( strcmp( config->ssl, "start_tls" ) == 0){
    /*TODO handle certif properly */
    ldap_tls_require_cert = LDAP_OPT_X_TLS_NEVER;
    rc = ldap_set_option(ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &ldap_tls_require_cert );
    if( rc != LDAP_OPT_SUCCESS ){
      LOGERROR( "ldap_set_option TLS_REQ_CERT returned (%d) \"%s\"\n", rc, ldap_err2string(rc) );
      goto connect_ldap_error;
    }
    rc = ldap_start_tls_s( ldap, NULL, NULL );
    if( rc != LDAP_SUCCESS && rc !=  LDAP_LOCAL_ERROR ){
      LOGERROR( "ldap_start_tls_s returned (%d) \"%s\"\n", rc, ldap_err2string(rc) );
      goto connect_ldap_error;
    }else if( rc == LDAP_LOCAL_ERROR ){
      LOGWARNING( "ldap_start_tls_s TLS context already exist\n" );
    }
  }
  return ldap;

connect_ldap_error:
  rc = ldap_unbind_ext_s( ldap, NULL, NULL );
  if( rc != LDAP_SUCCESS ){
    LOGERROR( "ldap_unbind_ext_s returned: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
  }
  return NULL;
}


/**
 * Search for a user's DN
 * Given a search_filter and context, will search for 
 */
char *
ldap_find_user( LDAP *ldap, auth_context_t *auth_context, const char *username ){
  struct timeval timeout;
  char *attrs[] = { NULL };
  char          *dn = NULL;
  LDAPMessage *e, *result;
  config_t *config = NULL;
  char *search_filter = NULL;
  int rc;
  char *userdn = NULL;

  /* arguments sanity check */
  if( !auth_context || !username || !ldap){
    LOGERROR("ldap_find_user missing required parameter\n");
    return NULL;
  }
  config = auth_context->config;
  
  /* initialise timeout values */
  timeout.tv_sec = config->timeout;
  timeout.tv_usec = 0;
  if( username && config->search_filter ){
    search_filter = str_replace(config->search_filter, "%u", username );
  }
  if( DODEBUG( auth_context->verb ) )
    LOGINFO( "Searching user using filter %s with basedn: %s\n", search_filter, config->basedn );

  rc = ldap_search_ext_s( ldap, config->basedn, LDAP_SCOPE_ONELEVEL, search_filter, attrs, 0, NULL, NULL, &timeout, 1000, &result );
  if( rc == LDAP_SUCCESS ){
    /* Check how many entries were found. Only one should be returned */
    int nbrow = ldap_count_entries( ldap, result );
    if( nbrow > 1 ){
      LOGERROR( "ldap_search_ext_s returned %d results, only 1 is supported\n", ldap_count_entries( ldap, result ) );
    }else if( nbrow == 0 ){
      LOGWARNING( "ldap_search_ext_s: unknown user %s\n", username );
    }else if( nbrow == 1 ){
      /* get the first entry (and only) */
      e =  ldap_first_entry( ldap, result );
      if( e != NULL ){
        dn = ldap_get_dn( ldap, e );
        if( DODEBUG( auth_context->verb ) )
          LOGINFO("found dn: %s\n", dn );
      }else{
        LOGERROR( "searched returned and entry but we could not retrieve it!!!\n" );
      }
    }
    /* free the returned result */
    ldap_msgfree( result );
  }
  if( dn ){
    userdn = strdup( dn );
    /* finally, if a DN was returned, free it */
    if( dn ) ldap_memfree( dn );
  }
  if( search_filter ) free( search_filter );
  return userdn;
}


int
ldap_group_membership( LDAP *ldap, auth_context_t *auth_context, char *userdn ){
  struct timeval timeout;
  char *attrs[] = { NULL };
  LDAPMessage *result;
  config_t *config = NULL;
  char *search_filter = NULL;
  int rc;
  int res = 1;
  char filter[]="(&(%s=%s)(%s))";

  /* arguments sanity check */
  if( !auth_context || !userdn || !ldap){
    LOGERROR("ldap_group_membership missing required parameter\n");
    return 1;
  }
  config = auth_context->config;
  
  /* initialise timeout values */
  timeout.tv_sec = config->timeout;
  timeout.tv_usec = 0;
  if( userdn && config->group_search_filter && config->member_attribute ){
    search_filter = strdupf(filter,config->member_attribute, userdn, config->group_search_filter);
  }
  if( DODEBUG( auth_context->verb ) )
    LOGINFO( "Searching user using filter %s with basedn: %s\n", search_filter, config->groupdn );

  rc = ldap_search_ext_s( ldap, config->groupdn, LDAP_SCOPE_ONELEVEL, search_filter, attrs, 0, NULL, NULL, &timeout, 1000, &result );
  if( rc == LDAP_SUCCESS ){
    /* Check how many entries were found. Only one should be returned */
    int nbrow = ldap_count_entries( ldap, result );
    if( nbrow < 1 ){
      LOGWARNING( "ldap_search_ext_s: user %s do not match group filter %s\n", userdn, search_filter );
    }else{
      if( DODEBUG( auth_context->verb ) )
        LOGINFO( "User %s matches %d groups with filter %s\n", userdn, nbrow, search_filter );
      res = 0;
    }
    /* free the returned result */
    ldap_msgfree( result );
  }
  if( search_filter ) free( search_filter );
  return res;
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

/**
 * thread handling user authentication
 */
void *
_authentication_thread( void *arg )
{

  LDAP *ldap = NULL;
  int rc;
  int res = OPENVPN_PLUGIN_FUNC_ERROR;

  char *userdn = NULL;
  auth_context_t *auth_context = ( auth_context_t * )arg;
  config_t *config = auth_context->config;

  /* Connection to LDAP backend */
  ldap = connect_ldap( auth_context );
  if( ldap == NULL ){
    LOGERROR( "Could not connect to URI %s\n", config->uri );
    goto auth_thread_exit;        
  }
  /* bind to LDAP server anonymous or authenticated */
  rc = ldap_binddn( ldap, config->binddn, config->bindpw );
  switch( rc ){
    case LDAP_SUCCESS:
      if( DODEBUG( auth_context->verb ) )
        LOGINFO( "ldap_sasl_bind_s %s success\n", config->binddn ? config->binddn : "Anonymous" );
        break;
    case LDAP_INVALID_CREDENTIALS:
      LOGERROR( "ldap_binddn: Invalid Credentials\n" );
      goto auth_thread_free;
    default:
      LOGERROR( "ldap_binddn: return value: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
      goto auth_thread_free;
  }

  userdn = ldap_find_user( ldap, auth_context, auth_context->username );
  if( !userdn ){
    LOGWARNING( "LDAP user *%s* was not found \n", auth_context->username );
    goto auth_thread_free;
  }
  
  /* OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY */
  if (auth_context && auth_context->config ){
      if (auth_context->username && strlen (auth_context->username) > 0 && auth_context->password){
      /** TODO authenticate user */
      if (DODEBUG (auth_context->verb)) {
        #if 0
          fprintf (stderr, "LDAP-AUTH: Authenticating Username:%s Password:%s\n", auth_context->username, auth_context->password);
        #else
          fprintf (stderr, "LDAP-AUTH: Authenticating Username:%s\n", auth_context->username );
        #endif
      }
      rc = ldap_binddn( ldap, userdn, auth_context->password );
      if( rc != LDAP_SUCCESS ){
        LOGERROR( "rebinding: return value: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
      }else{
        /* success, let set our return value to SUCCESS */
        if( DODEBUG( auth_context->verb ) )
          LOGINFO( "User *%s* successfully authenticate\n", auth_context->username );
        /* check if user belong to right groups */
        if( config->groupdn && config->group_search_filter && config->member_attribute ){
            rc = ldap_group_membership( ldap, auth_context, userdn );
            if( rc == 0 ){
              res = OPENVPN_PLUGIN_FUNC_SUCCESS;
            }
        }else{
          res = OPENVPN_PLUGIN_FUNC_SUCCESS;
        }
      }
    }
  }
auth_thread_free:
  rc = ldap_unbind_ext_s( ldap, NULL, NULL );
  if( rc != LDAP_SUCCESS ){
    LOGERROR( "ldap_unbind_ext_s: return value: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
  }
//func_v1_exit_free:
  if( userdn ) free( userdn );

auth_thread_exit:
  /* we need to write the result to  auth_control_file */
  if( DODEBUG(auth_context->verb ) ){
    LOGINFO( "User %s: Writing %c to file %s\n", auth_context->username, res == OPENVPN_PLUGIN_FUNC_SUCCESS ? '1' : '0', auth_context->auth_control_file );
  }
  rc = write_to_auth_control_file( auth_context->auth_control_file, res == OPENVPN_PLUGIN_FUNC_SUCCESS ? '1' : '0' );
  auth_context_free( auth_context );
  pthread_exit( NULL );
  return NULL;

}

OPENVPN_EXPORT int
openvpn_plugin_func_v1 (openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
  ldap_context_t *context = (ldap_context_t *) handle;
  auth_context_t *auth_context = NULL;
  pthread_t tid;
  action_t *action = NULL;

  
  config_t *config = context->config;
  int rc;
  int res = OPENVPN_PLUGIN_FUNC_ERROR;
  /* get username/password/auth_control_file from envp string array */
  const char *username = get_env ("username", envp);
  const char *password = get_env ("password", envp);
  const char *auth_control_file = get_env ( "auth_control_file", envp );

  if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY){

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
    /* FIXME might not need to dup config struct */
    auth_context->config = config_dup( config );
    auth_context->verb = context->verb;
    if( username ) auth_context->username = strdup( username );
    if( password ) auth_context->password = strdup( password );
    if( auth_control_file ) auth_context->auth_control_file = strdup( auth_control_file );
    /* If some argument were missing or could not be duplicate */
    if( !(auth_context->config && auth_context->username && auth_context->password && auth_context->auth_control_file ) ){
      auth_context_free( auth_context );
      return res;
    }
    auth_context_free( auth_context );
    action = action_new( );
    action->type = LDAP_AUTH_ACTION_AUTH;
    action_push( context->action_list, action );
#if 0
    /* now we can trigger our authentication thread */
    //la_memset( tid, 0, sizeof( pthread_t ) );
    rc = pthread_create( &tid, NULL, _authentication_thread, auth_context );
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
        pthread_detach( tid );
        res = OPENVPN_PLUGIN_FUNC_DEFERRED;
        if( DODEBUG( context->verb ) ){
          LOGINFO( "pthread_create(authentication_thread) successful, deferring authentication\n" );
        }
        break;
      default:
        LOGERROR( "pthread_create returned an unhandled value: %d\n", rc );
    }
#endif
    return OPENVPN_PLUGIN_FUNC_DEFERRED;
    
  }
  //const char *ip = get_env ("ifconfig_pool_remote_ip", envp );

  
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
  if (DODEBUG (context->verb))
    LOGINFO( "abort\n" );
  ldap_context_free( context );
}

void *
action_thread_mail_loop (void *c)
{
  ldap_context_t *context = c;
  action_t *action = NULL;
  int loop = 1;
  while( loop ){
    pthread_mutex_lock (&action_mutex);
    if (list_length (context->action_list) == 0){
      pthread_cond_wait (&action_cond, &action_mutex);
      if (DODEBUG (context->verb) ){
        LOGINFO( "Signal received, there is some action!\n");
      } 
    }
    /* get the action item */
    action = list_remove_item_at (context->action_list, 0);
    pthread_mutex_unlock (&action_mutex);
    /* TODO, do some action */
    if (action){
      switch (action->type){
        case LDAP_AUTH_ACTION_AUTH:
          fprintf (stderr, "Authentication requested\n");
          break;
        case LDAP_AUTH_ACTION_QUIT:
          fprintf (stderr, "Terminating\n");
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
