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

#define STRPRINT_IFSET(a,prefix) if(a) fprintf(stderr, "%s:\t%s\n", prefix, a);
#define STRDUP_IFNOTSET(a,b) if(!a && b) a=strdup(b);
//#define STRDUP_IFNOTSET_NOTNULL(a, b) if( b ) STRDUP_IFNOTSET(a,b)

void check_and_free( void *d ){
	if( d ) free( d );
}

void
config_set_default( config_t *c){
#ifdef OURI
  if(OURI) STRDUP_IFNOTSET(c->uri, OURI );
#endif
#ifdef OBASEDN
  STRDUP_IFNOTSET(c->basedn, OBASEDN );
#endif
#ifdef OBINDDN
  STRDUP_IFNOTSET(c->binddn, OBINDDN );
#endif
#ifdef OBINDPW
  STRDUP_IFNOTSET(c->bindpw, OBINDPW);
#endif
  if(!c->ldap_version) c->ldap_version =  OLDAP_VERSION;
#ifdef OSEARCH_FILTER
  STRDUP_IFNOTSET(c->search_filter, OSEARCH_FILTER );
#endif
#ifdef OSSL
  STRDUP_IFNOTSET(c->ssl, OSSL );
#endif
#ifdef OTLS_CACERTFILE
  STRDUP_IFNOTSET(c->tls_cacertfile, OTLS_CACERTFILE );
#endif 
#ifdef OTLS_CACERTDIR
  STRDUP_IFNOTSET(c->tls_cacertdir, OTLS_CACERTDIR );
#endif
#ifdef OTLS_CERTFILE
  STRDUP_IFNOTSET(c->tls_certfile, OTLS_CERTFILE );
#endif
#ifdef OTLS_CERTKEY
  STRDUP_IFNOTSET(c->tls_certkey, OTLS_CERTKEY );
#endif
#ifdef OTLS_CIPHERSUITE
  STRDUP_IFNOTSET(c->tls_ciphersuite, OTLS_CIPHERSUITE );
#endif
#ifdef OTLS_REQCERT
  STRDUP_IFNOTSET(c->tls_reqcert, OTLS_REQCERT );
#endif
#ifdef OTIMEOUT
  if( !c->timeout ) c->timeout = OTIMEOUT;
#endif
#ifdef OGROUPDN
  STRDUP_IFNOTSET(c->groupdn, OGROUPDN );
#endif
#ifdef OGROUP_SEARCH_FILTER
  STRDUP_IFNOTSET(c->group_search_filter, OGROUP_SEARCH_FILTER );
#endif
#ifdef OMEMBER_ATRIBUTE
  STRDUP_IFNOTSET(c->member_attribute, OMEMBER_ATRIBUTE );
#endif

}

config_t *
config_new( void ){
	config_t *c = malloc( sizeof( config_t ) );
	if( !c ) return NULL;
	memset( c, 0, sizeof( config_t ) );
	return c;
}

config_t *
config_dup( config_t *c ){
  config_t *nc = NULL;
  if( !c ) return NULL;
  nc = config_new( );
  if( !nc ) return NULL;

  if( c->uri ) nc->uri = strdup( c->uri );
  if( c->binddn ) nc->binddn = strdup( c->binddn );
  if( c->bindpw ) nc->bindpw = strdup( c->bindpw );
  if( c->basedn ) nc->basedn = strdup( c->basedn );
  nc->ldap_version = c->ldap_version;
  if( c->search_filter ) nc->search_filter = strdup( c->search_filter );
  if( c->ssl ) nc->ssl = strdup( c->ssl );
  if( c->tls_cacertfile ) nc->tls_cacertfile = strdup( c->tls_cacertfile );
  if( c->tls_cacertdir ) nc->tls_cacertdir = strdup( c->tls_cacertdir );
  if( c->tls_certfile ) nc->tls_certfile = strdup( c->tls_certfile );
  if( c->tls_certkey ) nc->tls_certkey = strdup( c->tls_certkey );
  if( c->tls_ciphersuite ) nc->tls_ciphersuite = strdup( c->tls_ciphersuite );
  if( c->tls_reqcert ) nc->tls_reqcert = strdup( c->tls_reqcert );

  nc->timeout = c->timeout;
  
  if( c->groupdn ) nc->groupdn = strdup( c->groupdn );
  if( c->group_search_filter ) nc->group_search_filter = strdup( c->group_search_filter );
  if( c->member_attribute ) nc->member_attribute = strdup( c->member_attribute );

  return nc;
}

void
config_free( config_t *c ){
	if( !c ) return;
	check_and_free( c->uri );
	check_and_free( c->binddn );
	check_and_free( c->bindpw );
	check_and_free( c->basedn );
  check_and_free( c->search_filter );
	/* TLS */
  check_and_free( c->ssl );
	check_and_free( c->tls_cacertfile );
	check_and_free( c->tls_cacertdir );
	check_and_free( c->tls_certfile );
	check_and_free( c->tls_certkey );
	check_and_free( c->tls_ciphersuite );
	check_and_free( c->tls_reqcert );
  /* Group */
  check_and_free( c->groupdn );
  check_and_free( c->group_search_filter );
  check_and_free( c->member_attribute );
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
      if( !strcmp( arg, "uri" ) ){
        STRDUP_IFNOTSET(c->uri, val );
      } else if ( !strcmp( arg, "binddn" ) ) {
        STRDUP_IFNOTSET(c->binddn, val );
      }else if ( !strcmp( arg, "bindpw" ) ) {
        STRDUP_IFNOTSET(c->bindpw, val );
      }else if ( !strcmp( arg, "basedn" ) ){
        STRDUP_IFNOTSET(c->basedn, val );
      }else if ( !strcmp( arg, "ldap_version" ) ){
        if(!c->ldap_version) c->ldap_version = atoi(val);
      }else if ( !strcmp( arg, "search_filter" ) ){
        STRDUP_IFNOTSET(c->search_filter, val );
      }else if ( !strcmp( arg, "ssl" ) ){
        STRDUP_IFNOTSET(c->ssl, val );        
      }else if ( !strcmp( arg, "tls_cacertfile" ) ){
        STRDUP_IFNOTSET(c->tls_cacertfile, val );
      }else if ( !strcmp( arg, "tls_cacertdir" ) ){
        STRDUP_IFNOTSET(c->tls_cacertdir, val );
      }else if ( !strcmp( arg, "tls_certfile" ) ){
        STRDUP_IFNOTSET(c->tls_certfile, val );
      }else if ( !strcmp( arg, "tls_certkey" ) ){
        STRDUP_IFNOTSET(c->tls_certkey, val );
      }else if ( !strcmp( arg, "tls_ciphersuite" ) ){
        STRDUP_IFNOTSET(c->tls_ciphersuite, val );
      }else if ( !strcmp( arg, "tls_reqcert" ) ){
        STRDUP_IFNOTSET(c->tls_reqcert, val );
      }else if( !strcmp( arg, "timeout" ) ){
        if( !c->timeout ) c->timeout = atoi(val);
      }else if( !strcmp( arg, "groupdn" ) ){
        STRDUP_IFNOTSET(c->groupdn, val );
      }else if( !strcmp( arg, "group_search_filter" ) ){
        STRDUP_IFNOTSET(c->group_search_filter, val );
      }else if( !strcmp( arg, "member_attribute" ) ){
        STRDUP_IFNOTSET(c->member_attribute, val );
      }

    }
		free( line );
	}
	close( fd );
	return 0;
}

void
config_dump( config_t *c){
  STRPRINT_IFSET(c->uri,"URI");
  STRPRINT_IFSET(c->basedn, "BaseDN");
  STRPRINT_IFSET(c->binddn,"BindDN");
  STRPRINT_IFSET(c->groupdn,"GroupDN");
  STRPRINT_IFSET(c->group_search_filter, "Group Search Filter");
  STRPRINT_IFSET(c->member_attribute,"Member Attribute");
  /* STRPRINT_IFSET(c->bindpw,"BindPW"); */
  /* TODO finish dumping info */
}
