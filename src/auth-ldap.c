/*
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 * 
 * auth-ldap.c
 * OpenVPN LDAP authentication plugin
 *
 *  Copyright (C) 2009 Emmanuel Bretelle <chantra@debuntu.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "cnf.h"
#include "utils.h"
#include "debug.h"

#define DODEBUG(verb) ((verb) >= 4)
#if 0
/* Command codes for foreground -> background communication */
#define COMMAND_VERIFY 0
#define COMMAND_EXIT   1

/* Response codes for background -> foreground communication */
#define RESPONSE_INIT_SUCCEEDED   10
#define RESPONSE_INIT_FAILED      11
#define RESPONSE_VERIFY_SUCCEEDED 12
#define RESPONSE_VERIFY_FAILED    13
#endif /* if 0 */

/**
 * Plugin state, used by foreground
 */
typedef struct ldap_context
{

  /* Parsed config info */
  config_t *config;

  /* Verbosity level of OpenVPN */
  int verb;
} ldap_context_t;


/**
 * Free LDAP context resources
 */

void
ldap_context_free( ldap_context_t *l ){
  if( !l ) return;
  if( l->config ) config_free( l->config );
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

#if 0
/* may be useful at a later stage */
/*
 * Socket read/write functions.
 */

static int
recv_control (int fd)
{
  unsigned char c;
  const ssize_t size = read (fd, &c, sizeof (c));
  if (size == sizeof (c))
    return c;
  else
    {
      /*fprintf (stderr, "AUTH-LDAP: DEBUG recv_control.read=%d\n", (int)size);*/
      return -1;
    }
}

static int
send_control (int fd, int code)
{
  unsigned char c = (unsigned char) code;
  const ssize_t size = write (fd, &c, sizeof (c));
  if (size == sizeof (c))
    return (int) size;
  else
    return -1;
}

static int
recv_string (int fd, char *buffer, int len)
{
  if (len > 0)
    {
      ssize_t size;
      memset (buffer, 0, len);
      size = read (fd, buffer, len);
      buffer[len-1] = 0;
      if (size >= 1)
	return (int)size;
    }
  return -1;
}

static int
send_string (int fd, const char *string)
{
  const int len = strlen (string) + 1;
  const ssize_t size = write (fd, string, len);
  if (size == len)
    return (int) size;
  else
    return -1;
}
#endif /* #if 0 */
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
	  fprintf (stderr, "AUTH-LDAP: daemonization failed\n");
	}
      else if (fd >= 3)
	{
	  dup2 (fd, 2);
	  close (fd);
	}
    }
}

#endif

/*
 * Close most of parent's fds.
 * Keep stdin/stdout/stderr, plus one
 * other fd which is presumed to be
 * our pipe back to parent.
 * Admittedly, a bit of a kludge,
 * but posix doesn't give us a kind
 * of FD_CLOEXEC which will stop
 * fds from crossing a fork().
 */
static void
close_fds_except (int keep)
{
  int i;
  closelog ();
  for (i = 3; i <= 100; ++i)
    {
      if (i != keep)
	close (i);
    }
}

/*
 * Usually we ignore signals, because our parent will
 * deal with them.
 */
static void
set_signals (void)
{
  signal (SIGTERM, SIG_DFL);

  signal (SIGINT, SIG_IGN);
  signal (SIGHUP, SIG_IGN);
  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);
  signal (SIGPIPE, SIG_IGN);
}

/*
 * Return 1 if query matches match.
 */
static int
name_value_match (const char *query, const char *match)
{
  while (!isalnum (*query))
    {
      if (*query == '\0')
	return 0;
      ++query;
    }
  return strncasecmp (match, query, strlen (match)) == 0;
}

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
  if( !context ) goto error;

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
        fprintf( stderr, "AUTH-LDAP: Unknown Option -%c !!\n", optopt );
        break;
      case ':':
        fprintf( stderr, "AUTH-LDAP: Missing argument for option -%c !!\n", optopt );
        break;
      default:
        fprintf(stderr, "AUTH-LDAP: ?? getopt returned character code 0%o ??\n", rc);
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


  return (openvpn_plugin_handle_t) context;

 error:
  if (context)
    ldap_context_free (context);
  return NULL;
}


/**
 * bind given ldap connection with username and password
 * Anonymous binding is achived by providing NULL username and password
 */

int
ldap_binddn( LDAP *ldap, char *username, char *password ){
  int rc;
  struct berval bv, *servcred = NULL;

  if( password && strlen(password) ){
    bv.bv_len = strlen(password);
    bv.bv_val = password;
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
connect_ldap( ldap_context_t *context ){
  LDAP *ldap;
  int rc;
  config_t *config = context->config;
  int ldap_tls_require_cert;
  struct berval bv, *bv2;
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
#if 0
  if( bind ){
    if (DODEBUG (context->verb))
      fprintf( stderr, "AUTH-LDAP: LDAP binding with user %s\n", (config->binddn ? config->binddn: "Anonymous" ) );
    
    rc = ldap_binddn( ldap, config->binddn, config->bindpw );
/** made redundant per ldap_binddn function
    if( config->bindpw && strlen(config->bindpw) ){
      bv.bv_len = strlen(config->bindpw);
      bv.bv_val = config->bindpw;
    }else{
      bv.bv_len = 0;
      bv.bv_val = NULL;
    }
    rc = ldap_sasl_bind_s( ldap, config->binddn, LDAP_SASL_SIMPLE, &bv, NULL, NULL, &bv2);
*/  
    switch( rc ){
      case LDAP_SUCCESS:
        if( DODEBUG( context->verb ) )
          fprintf( stderr, "AUTH-LDAP: ldap_sasl_bind_s success\n");
        break;
      case LDAP_INVALID_CREDENTIALS:
        LOGERROR( "ldap_binddn: Invalid Credentials\n" );
        goto connect_ldap_error;
      default:
        LOGERROR( "ldap_binddn: return value: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
        goto connect_ldap_error;
    }
    
  }
#endif
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
ldap_find_user( LDAP *ldap, ldap_context_t *context, char *username ){
  struct timeval timeout;
  char *attrs[] = { NULL };
  char          *dn = NULL;
  LDAPMessage *e, *result;
  config_t *config = NULL;
  char *search_filter = NULL;
  int rc;
  char *userdn = NULL;

  /* arguments sanity check */
  if( !context || !username || !ldap){
    LOGERROR("ldap_find_user missing required parameter\n");
    return NULL;
  }
  config = context->config;
  
  /* initialise timeout values */
  timeout.tv_sec = config->timeout;
  timeout.tv_usec = 0;
  if( username && config->search_filter ){
    search_filter = str_replace(config->search_filter, "%u", username );
  }
  if( DODEBUG( context->verb ) )
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
        if( DODEBUG( context->verb ) )
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
ldap_group_membership( LDAP *ldap, ldap_context_t *context, char *userdn ){
  struct timeval timeout;
  char *attrs[] = { NULL };
  LDAPMessage *e, *result;
  config_t *config = NULL;
  char *search_filter = NULL;
  int rc;
  int res = 1;
  char filter[]="(&(%s=%s)(%s))";

  /* arguments sanity check */
  if( !context || !userdn || !ldap){
    LOGERROR("ldap_group_membership missing required parameter\n");
    return 1;
  }
  config = context->config;
  
  /* initialise timeout values */
  timeout.tv_sec = config->timeout;
  timeout.tv_usec = 0;
  if( userdn && config->group_search_filter && config->member_attribute ){
    search_filter = strdupf(filter,config->member_attribute, userdn, config->group_search_filter);
  }
  if( DODEBUG( context->verb ) )
    LOGINFO( "Searching user using filter %s with basedn: %s\n", search_filter, config->groupdn );

  rc = ldap_search_ext_s( ldap, config->groupdn, LDAP_SCOPE_ONELEVEL, search_filter, attrs, 0, NULL, NULL, &timeout, 1000, &result );
  if( rc == LDAP_SUCCESS ){
    /* Check how many entries were found. Only one should be returned */
    int nbrow = ldap_count_entries( ldap, result );
    if( nbrow < 1 ){
      LOGWARNING( "ldap_search_ext_s: user %s do not match group filter %s\n", userdn, search_filter );
    }else{
      if( DODEBUG( context->verb ) )
        LOGINFO( "User %s matches %d groups with filter %s\n", userdn, nbrow, search_filter );
      res = 0;
    }
    /* free the returned result */
    ldap_msgfree( result );
  }
  if( search_filter ) free( search_filter );
  return res;
}


OPENVPN_EXPORT int
openvpn_plugin_func_v1 (openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
  ldap_context_t *context = (ldap_context_t *) handle;
  config_t *config = context->config;
  LDAP *ldap = NULL;
  int rc;
  int res = OPENVPN_PLUGIN_FUNC_ERROR;
  char *userdn = NULL;
  /* get username/password from envp string array */
  const char *username = get_env ("username", envp);
  const char *password = get_env ("password", envp);
  const char *ip = get_env ("ifconfig_pool_remote_ip", envp );


  /* required parameters check */
  if (!username){
    LOGERROR("No username supplied to OpenVPN plugin");
    return OPENVPN_PLUGIN_FUNC_ERROR;
  }
  
  /* Connection to LDAP backend */
  ldap = connect_ldap( context );
  if( ldap == NULL ){
    LOGERROR( "Could not connect to URI %s\n", config->uri );
    return OPENVPN_PLUGIN_FUNC_ERROR;        
  }
  /* bind to LDAP server anonymous or authenticated */
  rc = ldap_binddn( ldap, config->binddn, config->bindpw );
  switch( rc ){
    case LDAP_SUCCESS:
      if( DODEBUG( context->verb ) )
        LOGINFO( "ldap_sasl_bind_s %s success\n", config->binddn ? config->binddn : "Anonymous" );
      break;
    case LDAP_INVALID_CREDENTIALS:
      LOGERROR( "ldap_binddn: Invalid Credentials\n" );
      goto func_v1_exit;
    default:
      LOGERROR( "ldap_binddn: return value: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
      goto func_v1_exit;
  }

  userdn = ldap_find_user( ldap, context, username );
  if( !userdn ){
    LOGWARNING( "LDAP user *%s* was not found \n", username );
    goto func_v1_exit;
  }
  

  if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY && context && context->config ){
      if (username && strlen (username) > 0 && password){
      /** TODO authenticate user */
      if (DODEBUG (context->verb)) {
        #if 0
          fprintf (stderr, "AUTH-LDAP: Authenticating Username:%s Password:%s\n", username, password);
        #else
          fprintf (stderr, "AUTH-LDAP: Authenticating Username:%s\n", username );
        #endif
      }
     
      rc = ldap_binddn( ldap, userdn, password );
      if( rc != LDAP_SUCCESS ){
        LOGERROR( "rebinding: return value: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
      }else{
        /* success, let set our return value to SUCCESS */
        if( DODEBUG( context->verb ) )
          LOGINFO( "User *%s* successfully authenticate\n", username );
        /* check if user belong to right groups */
        if( config->groupdn && config->group_search_filter && config->member_attribute ){
            rc = ldap_group_membership( ldap, context, userdn );
            if( rc == 0 ){
              res = OPENVPN_PLUGIN_FUNC_SUCCESS;
            }
        }else{
          res = OPENVPN_PLUGIN_FUNC_SUCCESS;
        }
      }
    }
  }
func_v1_exit:
  rc = ldap_unbind_ext_s( ldap, NULL, NULL );
  if( rc != LDAP_SUCCESS ){
    LOGERROR( "ldap_unbind_ext_s: return value: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
  }
func_v1_exit_free:
  if( userdn ) free( userdn );
  return res;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
  ldap_context_t *context = (ldap_context_t *) handle;

  if (DODEBUG (context->verb))
    LOGINFO( "close\n" );

  ldap_context_free( context );
}

OPENVPN_EXPORT void
openvpn_plugin_abort_v1 (openvpn_plugin_handle_t handle)
{
  ldap_context_t *context = (ldap_context_t *) handle;
  if (DODEBUG (context->verb))
    LOGINFO( "abort\n" );
  ldap_context_free( context );
}

