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
#include "utils.h"
#include "defines.h"
#include "debug.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>  /* isspace */

#define STRPRINT_IFSET(a,prefix) if(a) fprintf(stderr, "%s:\t%s\n", prefix, a);
#define STRDUP_IFNOTSET(a,b) if(!a && b) a=strdup(b);
#define CHECK_IF_IN_PROFILE(a,b) if(!b){ \
LOGWARNING("%s is not defined within <profile></profile>. It will be ignored\n", a);\
free( line );\
continue;\
}

//#define STRDUP_IFNOTSET_NOTNULL(a, b) if( b ) STRDUP_IFNOTSET(a,b)

void check_and_free( void *d ){
	if( d ) la_free( d );
}

void
config_set_default( config_t *c){
#ifdef OURI
  if(OURI) STRDUP_IFNOTSET(c->ldap->uri, OURI );
#endif
#ifdef OBINDDN
  STRDUP_IFNOTSET(c->ldap->binddn, OBINDDN );
#endif
#ifdef OBINDPW
  STRDUP_IFNOTSET(c->ldap->bindpw, OBINDPW);
#endif
  if(!c->ldap->version) c->ldap->version =  OLDAP_VERSION;
#ifdef OSSL
  STRDUP_IFNOTSET(c->ldap->ssl, OSSL );
#endif
#ifdef OTLS_CACERTFILE
  STRDUP_IFNOTSET(c->ldap->tls_cacertfile, OTLS_CACERTFILE );
#endif 
#ifdef OTLS_CACERTDIR
  STRDUP_IFNOTSET(c->ldap->tls_cacertdir, OTLS_CACERTDIR );
#endif
#ifdef OTLS_CERTFILE
  STRDUP_IFNOTSET(c->ldap->tls_certfile, OTLS_CERTFILE );
#endif
#ifdef OTLS_CERTKEY
  STRDUP_IFNOTSET(c->ldap->tls_certkey, OTLS_CERTKEY );
#endif
#ifdef OTLS_CIPHERSUITE
  STRDUP_IFNOTSET(c->ldap->tls_ciphersuite, OTLS_CIPHERSUITE );
#endif
#ifdef OTLS_REQCERT
  STRDUP_IFNOTSET(c->ldap->tls_reqcert, OTLS_REQCERT );
#endif
#ifdef OTIMEOUT
  if( !c->ldap->timeout ) c->ldap->timeout = OTIMEOUT;
#endif
#ifdef OGROUPDN
  STRDUP_IFNOTSET(c->profile->groupdn, OGROUPDN );
#endif
#ifdef OGROUP_SEARCH_FILTER
  STRDUP_IFNOTSET(c->profile->group_search_filter, OGROUP_SEARCH_FILTER );
#endif
#ifdef OMEMBER_ATRIBUTE
  STRDUP_IFNOTSET(c->profile->member_attribute, OMEMBER_ATRIBUTE );
#endif

}

/**
 * ldap config
 */
void
ldap_config_free( ldap_config_t *c ){
  check_and_free( c->uri );
  check_and_free( c->binddn );
  check_and_free( c->bindpw );
  /* TLS */
  check_and_free( c->ssl );
  check_and_free( c->tls_cacertfile );
  check_and_free( c->tls_cacertdir );
  check_and_free( c->tls_certfile );
  check_and_free( c->tls_certkey );
  check_and_free( c->tls_ciphersuite );
  check_and_free( c->tls_reqcert );
  la_free( c );
}

ldap_config_t *
ldap_config_new( void ){
  ldap_config_t *c = la_malloc( sizeof( ldap_config_t ) );
  if( !c ) return NULL;
  la_memset (c, 0, sizeof( ldap_config_t ) );
  return c;
}

ldap_config_t *
ldap_config_dup( const ldap_config_t *c ){
  ldap_config_t *nc = ldap_config_new( );
  if( !nc)
      return NULL;

  if( c->uri ) nc->uri = strdup( c->uri );
  if( c->binddn ) nc->binddn = strdup( c->binddn );
  if( c->bindpw ) nc->bindpw = strdup( c->bindpw );
  nc->version = c->version;
  if( c->ssl ) nc->ssl = strdup( c->ssl );
  if( c->tls_cacertfile ) nc->tls_cacertfile = strdup( c->tls_cacertfile );
  if( c->tls_cacertdir ) nc->tls_cacertdir = strdup( c->tls_cacertdir );
  if( c->tls_certfile ) nc->tls_certfile = strdup( c->tls_certfile );
  if( c->tls_certkey ) nc->tls_certkey = strdup( c->tls_certkey );
  if( c->tls_ciphersuite ) nc->tls_ciphersuite = strdup( c->tls_ciphersuite );
  if( c->tls_reqcert ) nc->tls_reqcert = strdup( c->tls_reqcert );

  nc->timeout = c->timeout;

  return nc; 
}

/**
 * profile
 */
void
profile_config_free ( profile_config_t *c ){
  if( !c )
    return;

	check_and_free( c->basedn );
  check_and_free( c->search_filter );
  /* Group */
  check_and_free( c->groupdn );
  check_and_free( c->group_search_filter );
  check_and_free( c->member_attribute );
  check_and_free( c->default_pf_rules );
#ifdef ENABLE_LDAPUSERCONF
  check_and_free( c->default_profiledn );
#endif
	la_free( c );
}

void
profile_config_list_free_cb( void *data ){
  profile_config_t *c = data;
  profile_config_free( c );
}

profile_config_t *
profile_config_new ( void ){
  profile_config_t *c = la_malloc( sizeof( profile_config_t ) );
  if( !c ) return NULL;
  la_memset (c, 0, sizeof( profile_config_t ) );
  return c;
}

profile_config_t *
profile_config_dup( const profile_config_t *c ){
  profile_config_t *nc = NULL;

  nc = profile_config_new( );
  if( nc == NULL )
    return NULL;

  if( c->basedn ) nc->basedn = strdup( c->basedn );
  if( c->search_filter ) nc->search_filter = strdup( c->search_filter );
  nc->search_scope = c->search_scope;
  if( c->groupdn ) nc->groupdn = strdup( c->groupdn );
  if( c->group_search_filter ) nc->group_search_filter = strdup( c->group_search_filter );
  if( c->member_attribute ) nc->member_attribute = strdup( c->member_attribute );
  if( c->default_pf_rules ) nc->default_pf_rules = strdup( c->default_pf_rules );
  nc->enable_pf = c->enable_pf;
#ifdef ENABLE_LDAPUSERCONF
  if( c->default_profiledn ) nc->default_profiledn = strdup( c->default_profiledn );
#endif

  return nc;
}

/**
 * config
 */
config_t *
config_new( void ){
	config_t *c = malloc( sizeof( config_t ) );
	if( !c ) return NULL;
	memset( c, 0, sizeof( config_t ) );

  c->ldap = ldap_config_new( );
  c->profiles = list_new( );

  if( !(c->profiles && c->ldap) ){
    config_free( c );
    return NULL;
  }
	return c;
}

config_t *
config_dup( config_t *c ){
  config_t *nc = NULL;
  profile_config_t *pgc = NULL;
  list_item_t *item = NULL;
  ldap_config_t *l = NULL;

  if( !c ) return NULL;
  nc = config_new( );
  if( !nc ) return NULL;
  /* ldap */
  l = ldap_config_dup( c->ldap );
  ldap_config_free( nc->ldap );
  nc->ldap = l;

  /* profiles */
  for( item = list_first(c->profiles); item; item = item->next ){
    pgc = profile_config_dup( item->data );
    list_append( nc->profiles, pgc );
  }

  return nc;
}


void
config_free( config_t *c ){
	if( !c ) return;
  ldap_config_free( c->ldap );
  list_free( c->profiles, profile_config_list_free_cb );
  la_free( c );
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


char *
skip_whitespaces( char *l ){
  while(isspace(l[0]))
    l++;
  return l;
}

int
config_parse_file( const char *filename, config_t *c ){
	int fd;
	char *line;
  char *arg,*val;
  int in_profile = 0;
  int rc = 0;
  profile_config_t *p = NULL;
	fd = open( filename, O_RDONLY );
	if( fd == -1 ){
    LOGERROR( "Could not open file %s: (%d) %s\n", filename, errno, strerror( errno ) );
		return 1;
	}
  val = NULL;
	while ( ( line = f_readline( fd ) ) ){
    arg = skip_whitespaces( line );
    if( arg[0] == '#' || arg[0] == ';' ){
      free(line);
      continue;
    }
    if( !strncmp( arg, "<profile>", strlen( "<profile>" ) ) ){
      in_profile = 1;
      p = profile_config_new( );
      free(line);
      if( p == NULL ){
        LOGERROR( "Could not allocate memory for new profile\n" );
        rc = 1;
        break;
      }
      list_append( c->profiles, p );
      continue;
    }
    if( !strncmp( arg, "</profile>", strlen( "</profile>" ) ) ){
      in_profile = 0;
      STRDUP_IFNOTSET(p->search_filter, OSEARCH_FILTER);
      p = NULL;
      free(line);
      continue;
    }
    arg = strtok( arg, "=" );
    if(arg && *arg != '\n'){
      val = strtok( NULL, "\n");
      /* global conf -> ldap */
      if( !strcmp( arg, "uri" ) ){
        STRDUP_IFNOTSET(c->ldap->uri, val );
      } else if ( !strcmp( arg, "binddn" ) ) {
        STRDUP_IFNOTSET(c->ldap->binddn, val );
      }else if ( !strcmp( arg, "bindpw" ) ) {
        STRDUP_IFNOTSET(c->ldap->bindpw, val );
      }else if ( !strcmp( arg, "version" ) ){
        if(!c->ldap->version) c->ldap->version = atoi(val);
      }else if ( !strcmp( arg, "ssl" ) ){
        STRDUP_IFNOTSET(c->ldap->ssl, val );
      }else if ( !strcmp( arg, "tls_cacertfile" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_cacertfile, val );
      }else if ( !strcmp( arg, "tls_cacertdir" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_cacertdir, val );
      }else if ( !strcmp( arg, "tls_certfile" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_certfile, val );
      }else if ( !strcmp( arg, "tls_certkey" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_certkey, val );
      }else if ( !strcmp( arg, "tls_ciphersuite" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_ciphersuite, val );
      }else if ( !strcmp( arg, "tls_reqcert" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_reqcert, val );
      }else if( !strcmp( arg, "timeout" ) ){
        if( !c->ldap->timeout ) c->ldap->timeout = atoi(val);
      /* profile conf */
      }else if ( !strcmp( arg, "basedn" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->basedn, val );
      }else if ( !strcmp( arg, "search_filter" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->search_filter, val );
      }else if ( !strcmp( arg, "search_scope" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        if( !strcasecmp( val, "LDAP_SCOPE_BASE" ) ){
          p->search_scope = LA_SCOPE_BASE;
        }else if( !strcasecmp( val, "LDAP_SCOPE_ONELEVEL" ) ){
          p->search_scope = LA_SCOPE_ONELEVEL;
        }else if( !strcasecmp( val, "LDAP_SCOPE_SUBTREE" ) ){
          p->search_scope = LA_SCOPE_SUBTREE;
        }
      }else if( !strcmp( arg, "groupdn" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->groupdn, val );
      }else if( !strcmp( arg, "group_search_filter" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->group_search_filter, val );
      }else if( !strcmp( arg, "member_attribute" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->member_attribute, val );
      }else if( !strcmp( arg, "enable_pf" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        p->enable_pf = string_to_ternary( val );
      }else if( !strcmp( arg, "default_pf_rules" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->default_pf_rules, val );
#ifdef ENABLE_LDAPUSERCONF
      }else if( !strcmp( arg, "default_profiledn" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->default_profiledn, val );
#endif
      }else{
        LOGWARNING("Unrecognized option *%s=%s*\n", arg, val);
      }

    }
		free( line );
	}
	close( fd );
	return 0;
}

const char *
config_search_scope_to_string( ldap_search_scope_t scope){

  switch( scope ){
    case LA_SCOPE_BASE:
      return "BASE";
    case LA_SCOPE_ONELEVEL:
      return "ONELEVEL";
    case LA_SCOPE_SUBTREE:
      return "SUBTREE";
  }
  return NULL;
}
void
config_dump( config_t *c){
  fprintf( stderr, "Config Dump:\n*LDAP:*\n");
  STRPRINT_IFSET(c->ldap->uri,"\tURI");
  STRPRINT_IFSET(c->ldap->binddn,"\tBindDN");
  fprintf( stderr, "\tSSL:\t%s\n", c->ldap->ssl );
  fprintf( stderr, "\tLDAP VERSION:\t%d\n", c->ldap->version );
  fprintf( stderr, "\tLDAP TIMEOUT:\t%d\n", c->ldap->timeout );
#if 0
  fprintf( stderr, "*Default Profile:*\n" );
  STRPRINT_IFSET(c->profile->basedn, "\tBaseDN");
  fprintf( stderr, "\tEnable PF:\t%s\n", ternary_to_string(c->profile->enable_pf));
  fprintf( stderr, "\tSearch Scope:\t%s\n", config_search_scope_to_string( c->profile->search_scope ) );
  fprintf( stderr, "\tSearch filter:\t%s\n", c->profile->search_filter );
  STRPRINT_IFSET(c->profile->groupdn,"\tGroupDN");
  STRPRINT_IFSET(c->profile->group_search_filter, "\tGroup Search Filter");
  STRPRINT_IFSET(c->profile->member_attribute,"\tMember Attribute");
  STRPRINT_IFSET(c->profile->profiledn,"\tProfile DN");
#endif
  /* Dump each profiles */
  list_item_t *item;
  profile_config_t *p;
  for( item = list_first( c->profiles ); item; item = item->next){
    p = item->data;
    fprintf( stderr, "*Custom Profile:*\n" );
    STRPRINT_IFSET(p->basedn, "\tBaseDN");
    fprintf( stderr, "\tSearch Scope:\t%s\n", config_search_scope_to_string( p->search_scope ) );
    fprintf( stderr, "\tSearch filter:\t%s\n", p->search_filter );
    STRPRINT_IFSET(p->groupdn,"\tGroupDN");
    STRPRINT_IFSET(p->group_search_filter, "\tGroup Search Filter");
    STRPRINT_IFSET(p->member_attribute,"\tMember Attribute");
    STRPRINT_IFSET(p->profiledn,"\tProfile DN");
    fprintf( stderr, "\tEnable PF:\t%s\n", ternary_to_string(p->enable_pf));
    fprintf( stderr, "\tDefault PF rules:\t%s\n", p->default_pf_rules ? p->default_pf_rules : "Undefined" );
#ifdef ENABLE_LDAPUSERCONF
    fprintf( stderr, "\tDefault Profile DN:\t%s\n", p->default_profiledn ? p->default_profiledn : "Undefined" );
#endif

  }
}

int
config_is_pf_enabled( config_t *c ){
  int enabled = 0;
  list_item_t *item;

  for( item = list_first( c->profiles ); item; item = item->next ){
    profile_config_t *pc = item->data;
    if( pc->enable_pf == TERN_TRUE ){
      enabled = 1;
      break;
    }
  }
  return enabled;
}
int
config_is_pf_enabled_for_profile( config_t *c, profile_config_t *p ){
  return p->enable_pf == TERN_TRUE; 
}
