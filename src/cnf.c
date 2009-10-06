/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * cnf.c
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

#include "cnf.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

void check_and_free( void *d ){
	if( d ) free( d );
}

config_t *
config_new( void ){
	config_t *c = malloc( sizeof( config_t ) );
	if( !c ) return NULL;
	memset( c, 0, sizeof( config_t ) );
	return c;
}

void
config_free( config_t *c ){
	if( !c ) return;
	check_and_free( c->uri );
	check_and_free( c->binddn );
	check_and_free( c->bindpw );
	check_and_free( c->basedn );
	/* TLS */
	check_and_free( c->tls_cacertfile );
	check_and_free( c->tls_cacertdir );
	check_and_free( c->tls_certfile );
	check_and_free( c->tls_certkey );
	check_and_free( c->tls_ciphersuite );
	check_and_free( c->tls_reqcert );
	free( c );
}

char *
f_readline( int fd ){
	char *line = NULL;
	int length = 0;
	char c;
	int rc = 0;
	while( ( rc = read( fd, &c, 1 ) ) > 0 ){
		length++;
		line = realloc( line, length + 1 );
		line[length-1] = c;
		if( c == '\n' ) break;
	}
	if( rc < 0 ){
		/* an error occured */
		free(line);
		return NULL;
	}
	if(line) line[length] = '\0';
	return line;
}


int
config_parse_file( const char *filename, config_t *c ){
	int fd;
	char *line;

	fd = open( filename, O_RDONLY );
	if( fd == -1 ){
		return 1;
	}
	while ( ( line = f_readline( fd ) ) ){
		fprintf( stdout, "Read line: %s", line );
		free( line );
	}
	close( fd );
	return 0;
}
