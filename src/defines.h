/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * defines.h
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
#ifndef _DEFINES_H_
#define _DEFINES_H_

#define OURI						"ldap://localhost"
#define OLDAP_VERSION  3

//#define OBINDDN        NULL
//#define OBINDPW        NULL
#define OSEARCH_FILTER	"(uid=%u)"
//#define OSEARCH_FILTER NULL
#define OSSL          "off"
//#define OTLS_CACERTFILE
//#define OTLS_CACERTDIR
//#define OTLS_CERTFILE
//#define OTLS_CERTKEY
//#define OTLS_CIPHERSUITE
#define OTLS_REQCERT  "never"
#define OTIMEOUT  15

#endif
