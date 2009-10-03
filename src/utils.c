/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * utils.c
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

#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>

#define BACKSPACE 127

char *get_passwd( const char *prompt ){
	struct termios old, new;
	int size = 0;
	char c;
	char *pass = malloc( size + 1 );
	/* turn off echoing */
	if (tcgetattr (fileno (stdin), &old) != 0 )
        return NULL;
	new = old;
	//new.c_lflag &= ~ECHO || ECHOCTL;
	new.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON);
	if (tcsetattr (fileno ( stdin ), TCSAFLUSH, &new ) != 0 )
		return NULL;
	/* get the password */
	if( prompt ) fprintf( stdout, "%s", prompt );
	while( ( c = getc( stdin )) != '\n' ){
		if( c == BACKSPACE ){
			/* never happens as getc only read once \n is entered */ 
			if( size > 0 ) size--;
		}else{
			size ++;
			pass = realloc( pass, size + 1);
			*(pass+size-1) = c;
		}
	}
	*(pass+size) = '\0';
	/* Restore terminal. */
	tcsetattr (fileno ( stdin ), TCSAFLUSH, &old );
#if 0
	fprintf(stdout, "Password size: %d, strlen %d\n", size, strlen(pass) );
#endif
	return pass;
}


