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
#include "defines.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define STRPRINT_IFSET(a,prefix) if(a) fprintf(stdout, "%s:\t%s\n", prefix, a);
#define STRDUP_IFNOTSET(a,b) if(!a && b) a=strdup(b);
//#define STRDUP_IFNOTSET_NOTNULL(a, b) if( b ) STRDUP_IFNOTSET(a,b)

void check_and_free( void *d ){
	if( d ) free( d );
}

void
config_set_default( config_t *c){
  if(OURI) STRDUP_IFNOTSET(c->uri, OURI );
#ifdef OBASEDN
  STRDUP_IFNOTSET(c->basedn, OBASEDN );
#endif
#ifdef OBINDDN
  STRDUP_IFNOTSET(c->binddn, OBINDDN );
#endif
#ifdef OBINDPW
  STRDUP_IFNOTSET(c->bindpw, OBINDPW);
#endif
  if(!c->version) c->version =  OLDAP_VERSION;
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
  char *arg,*val;

	fd = open( filename, O_RDONLY );
	if( fd == -1 ){
		return 1;
	}
  val = NULL;
	while ( ( line = f_readline( fd ) ) ){
    arg = strtok( line, "=" );
    if(arg && *arg != '\n'){
      val = strtok( NULL, "\n");
      fprintf(stdout, "Found: %s/%s\n", arg, val );
      if( !strcmp( arg, "uri" ) ){
        c->uri = strdup( val );
      } else if ( !strcmp( arg, "binddn" ) ) {
        c->binddn = strdup( val );
      }else if ( !strcmp( arg, "bindpw" ) ) {
        STRDUP_IFNOTSET(c->bindpw, val );
      }else if ( !strcmp( arg, "basedn" ) ){
        STRDUP_IFNOTSET(c->basedn, val );
      }
    }
		free( line );
	}
	close( fd );
  config_dump( c );
	return 0;
}

void
config_dump( config_t *c){
  STRPRINT_IFSET(c->uri,"URI");
  STRPRINT_IFSET(c->basedn, "BaseDN");
  STRPRINT_IFSET(c->binddn,"BindDN");
  STRPRINT_IFSET(c->bindpw,"BindPW");
}
