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

#include <ldap.h>
#include <errno.h>

#include "debug.h"
#include "ldap_profile.h"
#include "utils.h"

ldap_profile_t *
ldap_profile_new( ){
  ldap_profile_t *l;
  l = la_malloc( sizeof( ldap_profile_t ) );
  if( !l ) return NULL;
  l->start_date = l->end_date = 0;
  l->pf_rules = NULL;
  l->config = NULL;
  l->push_reset = 0;
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
  if( l->pf_rules ) la_free( l->pf_rules );
  if( l->push_options ) list_free ( l->push_options, la_free );
  if( l->iroutes ) list_free( l->iroutes, la_free );
  if( l->config ) la_free( l->config );
  la_free( l );
}

ldap_account_t *
ldap_account_new( ){
  ldap_account_t *l;
  l = la_malloc( sizeof( ldap_account_t ) );
  if( !l ) return NULL;
  l->ifconfig_push = NULL;
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
  la_free( l );
}
int
ldap_account_load( LDAP *ldap, char *userdn, ldap_account_t *account ){
  return 0;
}
