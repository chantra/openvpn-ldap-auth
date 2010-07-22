/**
 * action.h
 * vim: tabstop=2 softtabstop=2 shiftwidth=2 expandtab
 * Copyright (C) 2009 Emmanuel Bretelle <chantra@debuntu.org>
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

#ifndef __ACTION_H__
#define __ACTION_H__

enum ldap_auth_action {
  LDAP_AUTH_ACTION_UNKNOWN = 0,
  LDAP_AUTH_ACTION_AUTH,
  LDAP_AUTH_ACTION_QUIT
};

typedef struct action{
  enum ldap_auth_action type;
  void *context; 
  void *client_context; /*this should not be freed, openvpn plugin call will take care of it */
  void (*context_free_func)( void *data ); 
} action_t;

extern action_t *action_new( void );
extern void action_free( void *action );

#endif /* __ACTION_H__ */
