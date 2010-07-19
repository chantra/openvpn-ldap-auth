/**
 * ldap_profile.h
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

#ifndef __LDAP_PROFILE_H__
#define __LDAP_PROFILE_H__

#include "cnf.h"
#include "list.h"
#include "utils.h"
#include "action.h"

typedef struct ldap LDAP;

typedef struct ldap_profile
{
  time_t               start_date;
  time_t               end_date;
  char                *pf_rules;
  list_t              *push_options;
  uint8_t              push_reset;
  list_t              *iroutes;
  char                *config;
} ldap_profile_t;


typedef struct ldap_account
{
  struct ldap_profile   *profile;
  char                  *ifconfig_push;
} ldap_account_t;

/** 
 * Allocate LDAP profile resources
 */
extern ldap_profile_t *ldap_profile_new( void );

/**
 * Free LDAP profile resources
 */
extern void ldap_profile_free( ldap_profile_t *l );

/**
 * Allocate LDAP account resouces
 */
extern ldap_account_t *ldap_account_new( void );

/**
 * Free LDAP account resources
 */
extern void ldap_account_free( ldap_account_t *l );

/**
 * Load user settings from LDAP
 */

extern int ldap_account_load( LDAP *ldap, char *userdn, ldap_account_t *account );
 
#endif /* __LDAP_PROFILE_H__ */
