/**
 * la_ldap.c
 * vim: tabstop=2 softtabstop=2 shiftwidth=2 expandtab
 * Copyright (C) 2010 Emmanuel Bretelle <chantra@debuntu.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define DODEBUG(verb) ((verb) >= 4)

#include <ldap.h>
#include <errno.h>
#include <openvpn/openvpn-plugin.h>

#include "debug.h"
#include "la_ldap.h"
#include "client_context.h"
#include "config.h"

#ifdef ENABLE_LDAPUSERCONF
#include "ldap_profile.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
/* write a value to pf_file */
int
write_to_pf_file( char *pf_file, char *value )
{
  int fd, rc;
  if( pf_file == NULL ){
    LOGERROR( "pf_file is null\n");
    return -1;
  }

  fd = open( pf_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU );
  if( fd == -1 ){
    LOGERROR( "Could not open file %s: (%d) %s\n", pf_file, errno, strerror( errno ) );
    return -1;
  }
  rc = write( fd, value, strlen(value) );
  if( rc == -1 ){
    LOGERROR( "Could not write value %s to  file %s: (%d) %s\n", value, pf_file, errno, strerror( errno ) );
  }else if( rc !=strlen(value) ){
    LOGERROR( "Could not write all of  %s to file %s\n", value, pf_file );
  }
  rc = close( fd );
  if( rc != 0 ){
    LOGERROR( "Could not close file %s: (%d) %s\n", pf_file, errno, strerror( errno ) );
  }
  return rc == 0;
}


void
ldap_context_free( ldap_context_t *l ){
  if( !l ) return;
  if( l->config ) config_free( l->config );
  if( l->action_list) list_free( l->action_list, action_free );
  free( l );
}

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


void
auth_context_free( auth_context_t *a ){
  if( !a ) return;
  if( a->username ) free( a->username );
  if( a->password ) free( a->password );
  if( a->auth_control_file ) free( a->auth_control_file );
  FREE_IF_NOT_NULL( a->pf_file );
  free( a );
  return;
}


auth_context_t *
auth_context_new( void ){
  auth_context_t *a = NULL;
  a = la_malloc( sizeof( auth_context_t ) ); 
  if( a ) la_memset( a, 0, sizeof( auth_context_t ) );  
  return a;
}

/**
 * la_ldap_set_timeout:
 * Set a timeout according to config
 */
void
la_ldap_set_timeout( config_t *conf, struct timeval *timeout){
  timeout->tv_sec = conf->ldap->timeout;
  timeout->tv_usec = 0;
}

/**
 * la_ldap_errno
 */
int
la_ldap_errno( LDAP *ldap ){
  int rc;
  ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &rc);
  return rc;
}


char *
ldap_find_user_for_profile( LDAP *ldap, ldap_context_t *ldap_context, const char *username, profile_config_t *p){
  char *userdn = NULL;
  struct timeval timeout;
  char *attrs[] = { NULL };
  char          *dn = NULL;
  LDAPMessage *e, *result;
  config_t *config = NULL;
  int rc;
  char *search_filter = NULL;
  int ldap_scope = 0;


  result = NULL;
  config = ldap_context->config;

  /* initialise timeout values */
  la_ldap_set_timeout( config, &timeout );

  if( username && config->profile->search_filter ){
    search_filter = str_replace(config->profile->search_filter, "%u", username );
  }
  if( DODEBUG( ldap_context->verb ) )
    LOGINFO( "Searching user using filter %s with basedn: %s\n", search_filter, p->basedn );
  if( p->search_scope == LA_SCOPE_BASE )
    ldap_scope = LDAP_SCOPE_BASE;
  else if( p->search_scope == LA_SCOPE_ONELEVEL )
    ldap_scope = LDAP_SCOPE_ONELEVEL;
  else if( p->search_scope == LA_SCOPE_SUBTREE )
    ldap_scope = LDAP_SCOPE_SUBTREE;
  rc = ldap_search_ext_s( ldap, p->basedn, ldap_scope, search_filter, attrs, 0, NULL, NULL, &timeout, 1000, &result );
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
        if( DODEBUG( ldap_context->verb ) )
          LOGINFO("found dn: %s\n", dn );
      }else{
        LOGERROR( "searched returned and entry but we could not retrieve it!!!\n" );
      }
    }
  }else{
    LOGERROR( "ldap_search_ext_s did not succeed (%d) %s\n", rc, ldap_err2string( rc ));
  }
  /* free the returned result */
  if( result != NULL ) ldap_msgfree( result );

  if( dn ){
    userdn = strdup( dn );
    /* finally, if a DN was returned, free it */
    if( dn ) ldap_memfree( dn );
  }
  if( search_filter ) free( search_filter );
  return userdn;

}
/**
 * Search for a user's DN
 * Given a search_filter and context, will search for
 */
char *
ldap_find_user( LDAP *ldap, ldap_context_t *ldap_context, const char *username, client_context_t *cc ){
  config_t *config = NULL;
  char *userdn = NULL;
  profile_config_t *p = NULL;
  list_item_t *item = NULL;

  cc->profile = NULL;

  /* arguments sanity check */
  if( !ldap_context || !username || !ldap){
    LOGERROR("ldap_find_user missing required parameter\n");
    return NULL;
  }

  config = ldap_context->config;

  if( list_length( config->profiles ) == 0 ){
    p = config->profile;
    userdn = ldap_find_user_for_profile( ldap, ldap_context, username, p );
    if( userdn ){
      cc->user_dn = strdup( userdn );
      cc->profile = p;
    }
  }else{
    for( item = list_first( config->profiles ); item; item = item->next ){
      p = item->data;
      userdn = ldap_find_user_for_profile( ldap, ldap_context, username, p );
      if( userdn ){
        cc->user_dn = strdup( userdn );
        cc->profile = p;
        break;
      }
    }
  }

  return userdn;
}


/**
 * Set up a connection to LDAP given the context configuration
 * Do not bind to LDAP, use ldap_bindn for that purpose
 */
LDAP *
connect_ldap( ldap_context_t *l ){
  LDAP *ldap;
  int rc;
  config_t *config = l->config;
  int ldap_tls_require_cert;
  struct timeval timeout;

  /* init connection to ldap */
  rc = ldap_initialize(&ldap, config->ldap->uri);
  if( rc!= LDAP_SUCCESS ){
    LOGERROR( "ldap_initialize returned (%d) \"%s\" : %s\n", rc, ldap_err2string(rc), strerror(errno) );
    goto connect_ldap_error;
  }
  /* Version */
  rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &(config->ldap->ldap_version));
  if( rc != LDAP_OPT_SUCCESS ){
    LOGERROR( "ldap_set_option version %d returned (%d) \"%s\"\n", config->ldap->ldap_version, rc, ldap_err2string(rc) );
    goto connect_ldap_error;
  }
  /* Timeout */
  la_ldap_set_timeout( config, &timeout);
  rc = ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout );
  if( rc != LDAP_OPT_SUCCESS ){
    LOGERROR( "ldap_set_option timeout %ds returned (%d) \"%s\"\n", config->ldap->timeout, rc, ldap_err2string(rc) );
    goto connect_ldap_error;
  }
  /* SSL/TLS */
  if( strcmp( config->ldap->ssl, "start_tls" ) == 0){
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
 * Check if userdn belongs to group
 */
int
ldap_group_membership( LDAP *ldap, ldap_context_t *ldap_context, char *userdn ){
  struct timeval timeout;
  char *attrs[] = { NULL };
  LDAPMessage *result;
  config_t *config = NULL;
  char *search_filter = NULL;
  int rc;
  int res = 1;
  char filter[]="(&(%s=%s)(%s))";

  /* arguments sanity check */
  if( !ldap_context || !userdn || !ldap){
    LOGERROR("ldap_group_membership missing required parameter\n");
    return 1;
  }
  config = ldap_context->config;
  
  /* initialise timeout values */
  la_ldap_set_timeout( config, &timeout);
  if( userdn && config->profile->group_search_filter && config->profile->member_attribute ){
    search_filter = strdupf(filter,config->profile->member_attribute, userdn, config->profile->group_search_filter);
  }
  if( DODEBUG( ldap_context->verb ) )
    LOGINFO( "Searching user using filter %s with basedn: %s\n", search_filter, config->profile->groupdn );

  rc = ldap_search_ext_s( ldap, config->profile->groupdn, LDAP_SCOPE_ONELEVEL, search_filter, attrs, 0, NULL, NULL, &timeout, 1000, &result );
  if( rc == LDAP_SUCCESS ){
    /* Check how many entries were found. Only one should be returned */
    int nbrow = ldap_count_entries( ldap, result );
    if( nbrow < 1 ){
      LOGWARNING( "ldap_search_ext_s: user %s do not match group filter %s\n", userdn, search_filter );
    }else{
      if( DODEBUG( ldap_context->verb ) )
        LOGINFO( "User %s matches %d groups with filter %s\n", userdn, nbrow, search_filter );
      res = 0;
    }
  }
  /* free the returned result */
  if ( result != NULL ) ldap_msgfree( result );
  if( search_filter ) free( search_filter );
  return res;
}


int
la_ldap_handle_authentication( ldap_context_t *l, action_t *a){
  LDAP *ldap = NULL;
  config_t *config = l->config;
  auth_context_t *auth_context = a->context;
  client_context_t *client_context = a->client_context;
  char *userdn = NULL;
  int rc;
  int res = OPENVPN_PLUGIN_FUNC_ERROR;

  /* Connection to LDAP backend */
  ldap = connect_ldap( l );
  if( ldap == NULL ){
    LOGERROR( "Could not connect to URI %s\n", config->ldap->uri );
    goto la_ldap_handle_authentication_exit;        
  }
  /* bind to LDAP server anonymous or authenticated */
  rc = ldap_binddn( ldap, config->ldap->binddn, config->ldap->bindpw );
  switch( rc ){
    case LDAP_SUCCESS:
      if( DODEBUG( l->verb ) )
        LOGINFO( "ldap_sasl_bind_s %s success\n", config->ldap->binddn ? config->ldap->binddn : "Anonymous" );
        break;
    case LDAP_INVALID_CREDENTIALS:
      LOGERROR( "ldap_binddn: Invalid Credentials\n" );
      goto la_ldap_handle_authentication_free;
    default:
      LOGERROR( "ldap_binddn: return value: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
      goto la_ldap_handle_authentication_free;
  }

  userdn = ldap_find_user( ldap, l, auth_context->username, client_context );
  if( !userdn ){
    LOGWARNING( "LDAP user *%s* was not found \n", auth_context->username );
    goto la_ldap_handle_authentication_free;
  }
  
  if (auth_context && l->config ){
      if (auth_context->username && strlen (auth_context->username) > 0 && auth_context->password){
      /** TODO authenticate user */
      if (DODEBUG (l->verb)) {
        #if 0
          LOGINFO ("LDAP-AUTH: Authenticating Username:%s Password:%s\n", auth_context->username, auth_context->password);
        #else
          LOGINFO ("LDAP-AUTH: Authenticating Username:%s\n", auth_context->username );
        #endif
      }
      rc = ldap_binddn( ldap, userdn, auth_context->password );
      if( rc != LDAP_SUCCESS ){
        LOGERROR( "rebinding: return value: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
      }else{
        /* success, let set our return value to SUCCESS */
        if( DODEBUG( l->verb ) )
          LOGINFO( "User *%s* successfully authenticate\n", auth_context->username );
#ifdef ENABLE_LDAPUSERCONF
        LOGWARNING( "ldap_account returned: %d\n", ldap_account_load_from_dn( l, ldap, userdn, client_context->ldap_account ));
        /* TODO check if user timeframe is allowed start_date, end_date */
        /* write to pf_file */
        if( client_context->ldap_account->profile->pf_rules && auth_context->pf_file ){
          write_to_pf_file( auth_context->pf_file, client_context->ldap_account->profile->pf_rules );
        }else{
          /* set up default pf_rules */
          write_to_pf_file( auth_context->pf_file, "[CLIENTS ACCEPT]\n[SUBNETS ACCEPT]\n[END]\n");
        }
        /* ldap_account_dump( client_context->ldap_account ); */
#endif
        /* check if user belong to right groups */
        if( config->profile->groupdn && config->profile->group_search_filter && config->profile->member_attribute ){
            rc = ldap_group_membership( ldap, l, userdn );
            if( rc == 0 ){
              res = OPENVPN_PLUGIN_FUNC_SUCCESS;
            }
        }else{
          res = OPENVPN_PLUGIN_FUNC_SUCCESS;
        }
      }
    }
  }
la_ldap_handle_authentication_free:
  rc = ldap_unbind_ext_s( ldap, NULL, NULL );
  if( rc != LDAP_SUCCESS ){
    LOGERROR( "ldap_unbind_ext_s: return value: %d/0x%2X %s\n", rc, rc, ldap_err2string( rc ) );
  }
  if( userdn ) free( userdn );

la_ldap_handle_authentication_exit:
  
  return res;

}
