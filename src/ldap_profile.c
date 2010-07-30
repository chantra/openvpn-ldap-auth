/**
 * ldap_profile.c
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

#include "debug.h"
#include "ldap_profile.h"
#include "utils.h"

#include <ldap.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>



ldap_profile_t *
ldap_profile_new( ){
  ldap_profile_t *l;
  l = la_malloc( sizeof( ldap_profile_t ) );
  if( !l ) return NULL;
  l->start_date = l->end_date = 0;
  /* PF */
  l->pf_client_default_accept = TERN_UNDEF;
  l->pf_subnet_default_accept = TERN_UNDEF;
  l->pf_client_rules = NULL;
  l->pf_subnet_rules = NULL;
  l->config = NULL;
  l->push_reset = TERN_UNDEF;
  l->iroutes = list_new( );
  l->push_options = list_new( );
  if( l->iroutes == NULL || l->push_options == NULL ){
    ldap_profile_free( l );
    return NULL;
  }
  return l;
}

void
ldap_profile_free( ldap_profile_t *l ){
  if( !l ) return;
  if( l->pf_client_rules ) la_free( l->pf_client_rules );
  if( l->pf_subnet_rules ) la_free( l->pf_subnet_rules );
  if( l->push_options ) list_free ( l->push_options, la_free );
  if( l->iroutes ) list_free( l->iroutes, la_free );
  if( l->config ) la_free( l->config );
  la_free( l );
}

void
ldap_profile_dump( ldap_profile_t *l ){

  fprintf(stdout, "Account profile:\n\
\tstart_date:\t\t%u\n\
\tend_date:\t\t%u\n\
\tpf_client_default_accept:\t\t%s\n\
\tpf_subnet_default_accept:\t\t%s\n\
\tpf_client_rules:\t\t%s\n\
\tpf_subnet_rules:\t\t%s\n\
\tpush_reset:\t\t%s\n\
\tconfig:\t\t%s\n",
    (unsigned int)l->start_date, (unsigned int)l->end_date,
    l->pf_client_default_accept == TERN_TRUE ? "ACCEPT" : l->pf_client_default_accept == TERN_FALSE ? "DROP": "Undef",
    l->pf_subnet_default_accept == TERN_TRUE ? "ACCEPT" : l->pf_subnet_default_accept == TERN_FALSE ? "DROP" : "Undef",
    l->pf_client_rules ? l->pf_client_rules : "None",
    l->pf_subnet_rules ? l->pf_subnet_rules : "None",
    l->push_reset == TERN_TRUE ? "TRUE" : l->push_reset == TERN_FALSE ? "FALSE" : "Undef",
    l->config ? l->config : "None");
  fprintf( stdout, "\tpush options:\n" );
  list_item_t *i;
  for(i = list_first( l->push_options ); i!=NULL; i = list_item_next( i ) ){
    fprintf( stdout, "\t\t\t%s\n", i->data ? (char *)(i->data) : "None");
  }
  fprintf( stdout, "\tiroutes:\n" );
  for(i = list_first( l->iroutes ); i!=NULL; i = list_item_next( i ) ){
    fprintf( stdout, "\t\t\t%s\n", i->data ? (char *)i->data : "None");
  }

}

ldap_account_t *
ldap_account_new( ){
  ldap_account_t *l;
  l = la_malloc( sizeof( ldap_account_t ) );
  if( !l ) return NULL;
  l->ifconfig_push = NULL;
  l->profile_dn = NULL;
  l->profile = ldap_profile_new( );

  if( l->profile == NULL ){
    ldap_account_free( l );
    return NULL;
  }
  return l;
}

void
ldap_account_free( ldap_account_t *l){
  if( !l ) return;
  if( l->profile ) ldap_profile_free( l->profile );
  if( l->ifconfig_push ) la_free( l->ifconfig_push );
  if( l->profile_dn ){
     la_free( l->profile_dn );
  }
  la_free( l );
}


void
ldap_account_dump( ldap_account_t *l ){
  fprintf(stdout, "LDAP account dump:\n\
\tifconfig_push:\t\t%s\n\
\tprofile_dn:\t\t%s\n",
          l->ifconfig_push ? l->ifconfig_push : "None",
          l->profile_dn ? l->profile_dn : "None");
  ldap_profile_dump( l->profile );
}

/**
 * Converts a LDAP boolean value to a ternary
 * If value is neither true/on/false/off
 * TERN_UNDEF is returned
 */
ternary_t
la_ldap_bool_to_ternary( char *value ){
  if( value == NULL )
    return TERN_UNDEF;

  if( strcasecmp( value, "true" ) == 0 || strcasecmp( value, "on" ))
    return TERN_TRUE;
  if( strcasecmp( value, "false" ) == 0 || strcasecmp( value, "off" ))
    return TERN_FALSE;
  return TERN_UNDEF;
}

/**
 * convert a LDAP GeneralizedTime string to a time_t.
 * t will be set to 0 if generalized time is
 * 00000000000000 or 00000101000000 and will
 * return success
 * Return 0 on success
 */
int
la_generalizedtime_to_time(const char *s, time_t *t)
{
  struct tm tm;

  if (s == NULL) return 0;

  if( strncasecmp( s, "00000000000000", sizeof("00000000000000") -1 ) == 0
      ||
      strncasecmp( s, "00000101000000", sizeof("00000101000000") -1 ) == 0 ){
    *t = 0;
    return 0;
  }
  memset(&tm, 0, sizeof(tm));
  if (sscanf(s, "%04u%02u%02u%02u%02u%02u",
       &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
       &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
    return 1;
  }
  tm.tm_year -= 1900;
  tm.tm_mon -= 1;

  *t = timegm(&tm);
  return 0;
}

/**
 * ldap_account_load_from_entry
 * Loads profile from an LDAP message
 */
int
ldap_account_load_from_entry( LDAP *ldap, LDAPMessage *e, ldap_account_t *account ){
  BerElement *berptr;
  char *attr;
  struct berval **vals;
  int rc = 0;
  int i = 0;
  time_t t;
  int ec;

  for( attr = ldap_first_attribute( ldap, e, &berptr ); attr != NULL; attr = ldap_next_attribute( ldap, e, berptr ) ){
    vals = ldap_get_values_len( ldap, e, attr );
    if( ldap_count_values_len( vals ) < 1 )
      goto ldap_account_load_from_entry_end_loop;

    if( strcasecmp( attr, "OvpnStartDate" ) == 0 && ldap_count_values_len( vals ) > 0){
      if( la_generalizedtime_to_time( vals[0]->bv_val, &t ) ){
        LOGERROR("Generalized time is not valid for OvpnStartDate");
        rc = 1;
      }else{
        account->profile->start_date = t;
      }
    }else if( strcasecmp( attr, "OvpnEndDate" ) == 0 ){
      if( la_generalizedtime_to_time( vals[0]->bv_val, &t ) ){
        LOGERROR("Generalized time is not valid for OvpnEndDate");
        rc = 1;
      }else{
        account->profile->end_date = t;
      }
    }else if( strcasecmp( attr, "OvpnPFRulesClientDefaultAccept" ) == 0 ){
      account->profile->pf_client_default_accept = la_ldap_bool_to_ternary( vals[0]->bv_val );
    }else if( strcasecmp( attr, "OvpnPFRulesSubnetDefaultAccept" ) == 0 ){
      account->profile->pf_subnet_default_accept = la_ldap_bool_to_ternary( vals[0]->bv_val );
    }else if( strcasecmp( attr, "OvpnPFRulesClient" ) == 0 ){
      if( account->profile->pf_client_rules ) la_free( account->profile->pf_client_rules );
      account->profile->pf_client_rules = strdup( vals[0]->bv_val );
    }else if( strcasecmp( attr, "OvpnPFRulesSubnet" ) == 0 ){
      if( account->profile->pf_subnet_rules ) la_free( account->profile->pf_subnet_rules );
      account->profile->pf_subnet_rules = strdup( vals[0]->bv_val );
    }else if( strcasecmp( attr, "OvpnCCDPushOption" ) == 0 ){
      for( i = 0; vals[i]; i++){
        list_append( account->profile->push_options, (void *)strdup( vals[i]->bv_val ) );
      }
    }else if( strcasecmp( attr, "OvpnCCDPushReset" ) == 0 ){
      account->profile->push_reset = la_ldap_bool_to_ternary( vals[0]->bv_val );
    }else if( strcasecmp( attr, "OvpnCCDIRoute" ) == 0 ){
      for( i = 0; vals[i]; i++){
        list_append( account->profile->iroutes, (void *) strdup( vals[i]->bv_val ) );
      }
    }else if( strcasecmp( attr, "OvpnCCDConfig" ) == 0 ){
      if( account->profile->config ) la_free( account->profile->config );
      account->profile->config = strdup( vals[0]->bv_val );
    }
ldap_account_load_from_entry_end_loop:
    ldap_value_free_len( vals );
    ldap_memfree( attr );
  }
  /**
   * ldap_first_attribute, ldap_next_attribute return NULL
   * on error or end of attribute list
   * we need to check out la_ldap_errno value to know
   * if we exited the loop on error or success
   */
  ec = la_ldap_errno( ldap );
  if( ec != LDAP_SUCCESS){
    rc = 1;
    LOGERROR( "Error retrieving attributes (%d): %s\n", ec, ldap_err2string(ec) );
  }
  if( berptr != NULL ) ber_free( berptr, 0 );

  return rc;
}

/**
 * ldap_account_load_from_dn
 * Load a user config from LDAP database
 * returns 0 on success, non 0 otherwise
 */
int
ldap_account_load_from_dn( ldap_context_t *ldap_context, LDAP *ldap, char *dn, ldap_account_t *account ){
  /**
   * retrieve info from user settings
   * if user has a profile, get info from that profile
   */
  struct timeval timeout;
  char *attrs[] = { NULL };
  LDAPMessage *e, *result;
  config_t *config = NULL;
  uint8_t is_account = 0;
  int rc;

  /* if a NULL value was given for account, no action is taken */
  if( account == NULL )
    return 0;
  result = NULL;
  if (!ldap || !ldap_context){
    LOGERROR("ldap_account_load missing required parameter\n");
    return 1;
  }
  config = ldap_context->config;
  la_ldap_set_timeout( config, &timeout );
  rc = ldap_search_ext_s( ldap, dn, LDAP_SCOPE_BASE, NULL,
                      attrs, 0,NULL, NULL,
                      &timeout, 2, &result );
  if( rc != LDAP_SUCCESS ){
    LOGERROR( "ldap_search_ext_s: did not succeed for dn %s, (%d): %s\n",
                dn, rc, ldap_err2string( rc ) );
    ldap_msgfree( result );
    return 1;
  }
  int nbrow = ldap_count_entries( ldap, result );
  if( nbrow != 1 ){
    LOGERROR( "ldap_search_ext_s: returned %d results, only 1 expected\n", nbrow );
    ldap_msgfree( result );
    return 1;
  }

  /** for a user account, we first check if there is a
   * profile we should read data from.
   * Then, we read profile data
   */
  e =  ldap_first_entry( ldap, result );
  if( e == NULL ){
    int ec = la_ldap_errno( ldap );
    LOGERROR( "ldap_first_entry did not succeed (%d): %s\n", ec, ldap_err2string( ec ) );
    ldap_msgfree( result );
    return 1;
  }
  struct berval **vals = ldap_get_values_len( ldap, e, "objectClass" );
  int i;
  for( i = 0; vals[i]; i++ ){
    if( strcasecmp( vals[i]->bv_val, "OpenVPNAccount" ) == 0 ){
      is_account = 1;
      break;
    }
  }
  ldap_value_free_len( vals );
  if( is_account ){
    if( account->profile_dn ){
      la_free( account->profile_dn );
      account->profile_dn = NULL;
    }
    if( ( vals = ldap_get_values_len( ldap, e, "ovpnprofile" ) ) ){
      if ( ldap_count_values_len( vals ) > 0 ){
        /** We have a profile, read profile values from DN */
        account->profile_dn = strdup( vals[0]->bv_val );
      }
      ldap_value_free_len( vals );

      if( account->profile_dn ){
        ldap_account_load_from_dn( ldap_context, ldap, account->profile_dn, account );
      }
    }else{
      /* reset ld_errno */
      int ec = LDAP_SUCCESS;
      ldap_set_option( ldap, LDAP_OPT_ERROR_NUMBER, &ec );
    }
  }
  ldap_account_load_from_entry( ldap, e, account );
  ldap_msgfree( result );
  return 0;
}

/**
 * ldap_account_get_options_to_string
 * returns NULL is no option is to be pushed
 */

char *
ldap_account_get_options_to_string( ldap_account_t *account ){

  uint8_t tot_size = 0;
  list_item_t *elem = NULL;
  char *res = NULL;
  if (account->profile->push_reset == TERN_TRUE)
      tot_size += sizeof("push-reset\n");
  if (account->ifconfig_push)
      tot_size += sizeof("ifconfig \n") + strlen(account->ifconfig_push);

  if ( list_length (account->profile->iroutes) > 0 )
    for(elem = list_first( account->profile->iroutes ); elem; elem = list_item_next( elem ) ){
      tot_size += sizeof("iroute \n") + strlen( (char *)elem->data );
    }

  if ( list_length (account->profile->push_options) > 0 )
    for(elem = list_first( account->profile->push_options ); elem; elem = list_item_next( elem ) ){
      tot_size += sizeof("push \"\"\n") + strlen( (char *)elem->data );
    }

  if ( tot_size == 0 )
    return NULL;

  tot_size += 1;
  res = la_malloc( tot_size );
  la_memset( res, 0, tot_size);

  if (account->profile->push_reset == TERN_TRUE)
    strcat( res, "push-reset\n");
  if (account->ifconfig_push)
    strcatf( res, "ifconfig %s\n", account->ifconfig_push );

  if ( list_length (account->profile->iroutes) > 0 )
    for(elem = list_first( account->profile->iroutes ); elem; elem = list_item_next( elem ) ){
      strcatf( res, "iroute %s\n", (char *)elem->data );
    }

  if ( list_length (account->profile->push_options) > 0 )
    for(elem = list_first( account->profile->push_options ); elem; elem = list_item_next( elem ) ){
      strcatf( res, "push \"%s\"\n", (char *)elem->data );
    }

  return res;
}


/**
 * return a static string interpreting
 * LDAP pf_[client|subnet]_default_accept
 * suitable for pf_file insertion
 */
char *
la_ldap_default_rule_to_string( ternary_t rule ){
  if( rule == TERN_TRUE )
    return "ACCEPT";
  if( rule == TERN_FALSE )
    return "DROP";
  return "";
}

char *
ldap_profile_generate_pf_rules( ldap_profile_t *lp ){
  char *res = NULL;
  res = strdupf("[CLIENTS %s]\n\
%s\n\
[SUBNETS %s]\n\
%s\n\
[END]\n",
      la_ldap_default_rule_to_string( lp->pf_client_default_accept ),
      lp->pf_client_rules ? lp->pf_client_rules : "",
      la_ldap_default_rule_to_string( lp->pf_subnet_default_accept ),
      lp->pf_subnet_rules ? lp->pf_subnet_rules : "" );
  LOGDEBUG("pf_rules = %s\n", res);
  return res;
}

int
ldap_profile_write_to_pf_file( char *pf_file, char *value )
{
  int fd, rc = 0;
  if( pf_file == NULL ){
    LOGERROR( "pf_file is null\n");
    return 1;
  }

  fd = open( pf_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU );
  if( fd == -1 ){
    LOGERROR( "Could not open file %s: (%d) %s\n", pf_file, errno, strerror( errno ) );
    return 1;
  }
  rc = write( fd, value, strlen(value) );
  if( rc == -1 ){
    LOGERROR( "Could not write value %s to  file %s: (%d) %s\n", value, pf_file, errno, strerror( errno ) );
    rc = 1;
  }else if( rc !=strlen(value) ){
    LOGERROR( "Could not write all of  %s to file %s\n", value, pf_file );
    rc = 1;
  }else{
    rc = 0;
  }
  if( close( fd ) != 0 ){
    LOGERROR( "Could not close file %s: (%d) %s\n", pf_file, errno, strerror( errno ) );
  }
  return rc;
}


/**
 * la_ldap_handle_pf_file
 * Given the plugin config and the client_context
 * will write to pf_file the right
 */
int
ldap_profile_handle_pf_file(config_t *c, profile_config_t *p, ldap_profile_t *lp, char *pf_file){
  int rc = 0;
  /* check if pf is enabled */
  LOGDEBUG("PF enable for this profile: %s\n",
        p->enable_pf == TERN_TRUE ? "TRUE" : "FALSE" );
  /* write to pf_file */
  if( pf_file == NULL && config_is_pf_enabled(c) ){
    LOGERROR("PF is enabled but environment pf_file variable is NULL.\n");
    return 1;
  }else if( pf_file ){
    if( p->enable_pf == TERN_TRUE ){
      /* We only write PF rules from LDAP if
       * pf_client_default_accept and pf_subnet_default_accept
       * are defined
       */
      if( lp->pf_client_default_accept != TERN_UNDEF && lp->pf_subnet_default_accept != TERN_UNDEF ){
        char *pf_rules = NULL;
        pf_rules = ldap_profile_generate_pf_rules( lp );
        if( pf_rules ){
          rc = ldap_profile_write_to_pf_file( pf_file, pf_rules );
          la_free( pf_rules );
        }else{
          LOGERROR("ldap_profile_handle_pf_file: could not generate pf_rules\n");
          return 1;
        }
      }else if( p->default_pf_rules ){
        char *rules = str_replace_all( p->default_pf_rules, "\\n", "\n" );
        int res = ldap_profile_write_to_pf_file( pf_file, rules );
        if( rules ) la_free( rules );
        return res;
      }else{
        /* set up default pf_rules */
        /*
         * If pf_client_default_accept or pf_subnet_default_accept
         * is not defined, we default to openvpn standard behaviour:
         * allow everything
         */
        return ldap_profile_write_to_pf_file( pf_file, PF_ALLOW_ALL);
      }
    }else{
        /* profile has PF disabled */
        return ldap_profile_write_to_pf_file( pf_file, PF_ALLOW_ALL );
    }
  }
  return rc;
}

/**
 * la_ldap_handle_allowed_timeframe
 * check if a user LDAP profile can log in
 * return 0 on success
 */
int
ldap_profile_handle_allowed_timeframe( ldap_profile_t *p ){
  time_t now = time(NULL);
  if( !( p->start_date == 0 || p->start_date < now )
      ||
      !( p->end_date == 0 || p->end_date > now ) ){
    LOGINFO("user time period: %d/%d is not allowed to connect at %d\n", p->start_date, p->end_date, now);
    return 1;
  }
  LOGINFO("user time period: %d/%d is allowed to connect at %d\n", p->start_date, p->end_date, now);
  return 0;
}



