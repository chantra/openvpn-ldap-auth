/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * types.h
 *
 * Copyright (C) 2010 Emmanuel Bretelle <chantra@debuntu.org>
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
 *
 */

#ifndef _TYPES_H_
#define _TYPES_H_

typedef enum ternary {
  TERN_FALSE = -1,
  TERN_UNDEF = 0,
  TERN_TRUE = 1
} ternary_t;

#define ternary_to_string(x) x == TERN_FALSE ? "False" : x == TERN_UNDEF ? "Undef" : "True"
#define string_to_ternary(x) strcasecmp(x,"true") || strcasecmp(x,"on") || strcasecmp(x,"1") ? TERN_TRUE : TERN_FALSE
/* bool definitions */
#ifndef bool
#define bool int
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#define BOOL_CAST(x) ((x) ? (true) : (false))

#endif
