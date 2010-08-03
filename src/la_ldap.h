/**
 * la_ldap.h
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

#ifndef __LA_LDAP_H__
#define __LA_LDAP_H__

#include "cnf.h"
#include "list.h"
#include "utils.h"
#include "action.h"

/* ldap forward declaration */
typedef struct ldap LDAP;

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
  char            *username;
  char            *password;
  char            *auth_control_file;
  char            *pf_file;
} auth_context_t;

/**
 * Allocate Authentication context resources
 */
extern auth_context_t * auth_context_new( void );

/**
 * Free Authentication context resources
 */
extern void auth_context_free( auth_context_t *a );

/**
 * Free LDAP context resources
 */
extern void ldap_context_free( ldap_context_t *l );
/**
 * Allocate LDAP context resources
 * return NULL on memory allocation issue
 */

extern ldap_context_t * ldap_context_new( void );

/**
 * Set a timeout according to config
 */
extern void la_ldap_set_timeout( config_t *conf, struct timeval *timeout);
/**
 * handle authentication action
 * takes care of:
 *  - checking if user exists
 *  - user/pass is correct
 *  - load LDAP profile data if any
 *  - write PF rules if needed
 */
extern int la_ldap_handle_authentication( ldap_context_t *l, action_t *a);

/**
 * return ldap's ld_errno value
 */
extern int la_ldap_errno( LDAP *ldap );
#endif /* __LA_LDAP_H__ */
