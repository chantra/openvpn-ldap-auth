/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * cnf.h
 *
 * Copyright (C) 2009 Emmanuel Bretelle <chantra@debuntu.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _CNF_H_
#define _CNF_H_

#include "list.h"
#include "types.h"
#include "config.h"


typedef enum ldap_search_scope{
  LA_SCOPE_BASE = 0,
  LA_SCOPE_ONELEVEL,
  LA_SCOPE_SUBTREE
} ldap_search_scope_t;
/**
 * ldap_config
 * defines how to connect to an ldap server
 */

typedef struct ldap_config{
  char			*uri;

  char			*binddn;
  char			*bindpw;

  int				ldap_version;
  int       timeout;

  /* TLS/SSL */
  char			*ssl;
  char			*tls_cacertfile;
  char			*tls_cacertdir;
  char			*tls_certfile;
  char			*tls_certkey;
  char			*tls_ciphersuite;
  char			*tls_reqcert;


} ldap_config_t;

typedef struct profile_config{
  char        *basedn;
  char        *search_filter;
  ldap_search_scope_t search_scope;
  /* group membership */
  char        *groupdn;
  char        *group_search_filter;
  char        *member_attribute;
  char        *profiledn;
  /* packet filtering */
  ternary_t    enable_pf;
  char        *default_pf_rules;
#ifdef ENABLE_LDAPUSERCONF
  /* default profiledn for ldap user conf */
  char        *default_profiledn;
#endif
} profile_config_t;

/**
 * config hold a reference to global_config
 * and the different profiles to use
 */
typedef struct config{
  ldap_config_t    *ldap;
  list_t    *profiles;
} config_t;

extern int config_parse_file( const char *filename, config_t *c );

extern config_t *config_new( void );
extern config_t *config_dup( config_t *c );
extern void config_free( config_t *c );
extern void config_dump( config_t *c );
extern void config_set_default( config_t *c );
extern int config_is_pf_enabled( config_t *c );
extern int config_is_pf_enabled_for_profile( config_t *c, profile_config_t *p );
#endif /* _CNF_H_ */
