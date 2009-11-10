/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * utils.h
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
 *
 */

#ifndef _UITLS_H_
#define _UTILS_H_

#include <stdlib.h>

/* memory allocation */
extern void *la_malloc( size_t size );
extern void la_free( void *ptr );
extern void *la_memset( void *s, int c, size_t n );

/*
 *  Duplicates the string specified by the format-string [fmt].
 *  Returns the new string, or NULL if out of memory.
 *  The caller is responsible for freeing this new string.
 */
extern char *strdupf (const char *fmt, ...);


/*
 * Create a new string with [substr] being replaced by [replacement] in [string]
 * Returns the new string, or NULL if out of memory.
 * The caller is responsible for freeing this new string.
 */
extern char *str_replace( const char *string, const char *substr, const char *replacement );
/*
 * Reads a password from stdin, the password is not echoed
 * to stdout
 */

extern char *get_passwd( const char *prompt );

#endif /* _UTILS_H_ */

