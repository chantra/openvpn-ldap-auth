/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * openvpn-ldap-rules.c
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
#include "debug.h"
#include "defines.h"
#include "utils.h"
#include "cnf.h"


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
#include <sys/types.h>


#include <unistd.h>		/* getopt */
#include <string.h>		/* strdup */
#include <libgen.h>		/* basename */

int debug = 0;
#define printdebug( fmt, args... ) _printdebug( debug, fmt, ##args )

void usage( char *prog ){
	char *prg = strdup( prog );
	char *name = basename( prog );
	fprintf( stderr, "USAGE: %s [-h] [-d] [-c configfile] [-D binddn] [-H ldap_uri] [-Z]\n\
\t-h:\tprint this help\n\
\t-c:\tconfig file\n\
\t-d:\tadd debugging info\n\
\t-H:\tLdap server uri, default: %s\n\
\t-D:\tBindDN, default: None\n\
\t-Z:\tUse START_TLS\n", name, URI);
	free( prg );
}


int
main( int argc, char **argv){
	LDAP		*ldap;
	int ldap_version = 3;
	int ldap_tls_require_cert = LDAP_OPT_X_TLS_HARD;
	int rc;
	char *bind_user = NULL;
	char *password = NULL;
  char *configfile = NULL;
  config_t  *config = NULL;
	struct berval bv, *bv2;
  char *filter = NULL;

	/* default values */
	char		*ldap_uri = URI;
	int			start_tls = TLSEnable; 

  config = config_new( );

	while ( ( rc = getopt ( argc, argv, "H:D:c:WZhdv" ) ) != - 1 ){
		switch( rc ) {
			case 'h':
				usage( argv[0] );
				return 0;
			case 'H':
				ldap_uri = optarg;
				break;
			case 'Z':
				start_tls = 1;
				break;
			case 'D':
				bind_user = optarg;
				break;
			case 'W':
				password = get_passwd("Password: ");
				/*printdebug( "Password is %s: length: %d\n", password, strlen(password) );*/
				break;
			case 'd':
				debug = 1;
				break;
      case 'c':
        configfile = optarg;
        config_parse_file( optarg, config );
        break;
			case '?':
				fprintf( stderr, "Unknwon Option -%c !!\n", optopt );
				break;
			default:
				abort();
		}
	}
  if (optind < argc){
    filter = argv[optind];
  }

	rc = ldap_initialize(&ldap, ldap_uri);
	if( rc!= LDAP_SUCCESS ){
		ERROR( "ERROR: ldap_initialize returned (%d) \"%s\" : %s\n", rc, ldap_err2string(rc), strerror(errno) );
		return 1;
	}
	
	rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
	if( rc != LDAP_OPT_SUCCESS ){
		ERROR( "ERROR: ldap_set_option returned (%d) \"%s\"\n", rc, ldap_err2string(rc) );
		return 1;
	}
	
	if( start_tls == 1){
		printdebug( "Starting TLS\n" );
		ldap_tls_require_cert = LDAP_OPT_X_TLS_NEVER;
		rc = ldap_set_option(ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &ldap_tls_require_cert );
		if( rc != LDAP_OPT_SUCCESS ){
			ERROR( "ERROR: ldap_set_option TLS_REQ_CERT returned (%d) \"%s\"\n", rc, ldap_err2string(rc) );
			return 1;
		}
		rc = ldap_start_tls_s( ldap, NULL, NULL );
		if( rc != LDAP_SUCCESS && rc !=  LDAP_LOCAL_ERROR ){
			ERROR( "ERROR: ldap_start_tls_s returned (%d) \"%s\"\n", rc, ldap_err2string(rc) );
			return 2;
		}
	}
	if( password && strlen(password) ){
		bv.bv_len = strlen(password);
		bv.bv_val = password;
	}else{
		bv.bv_len = 0;
		bv.bv_val = NULL;
	}
	printdebug("Connecting with user %s\n", bind_user ? bind_user : "NULL" );

	rc = ldap_sasl_bind_s( ldap, bind_user, LDAP_SASL_SIMPLE, &bv, NULL, NULL, &bv2);
	switch( rc ){
		case LDAP_SUCCESS:
			break;
		case LDAP_INVALID_CREDENTIALS:
			WARN( "Invalid credentials" );
			goto exit;
		default:
			WARN( "Unknown return value: %d/0x%2X %s", rc, rc, ldap_err2string( rc ) );
			goto exit;
	}
	if( bv2 ){
		fprintf(stderr, "bv2: %*s\n", (int)bv2->bv_len, bv2->bv_val);
	}
	fprintf(stdout, "Bind returned: %d\n", rc );


	LDAPMessage *e, *result;
	char *attrs[] = {"cn", "givenname","ovpnAllow", NULL};
  /*
  char **attrs = NULL; -> returns all attributes
  char *attrs[] = {"+", NULL} -> returns extended attributes like modifiername...
  */
	struct timeval timeout;
	timeout.tv_sec = 15;
	timeout.tv_usec = 0;
	char         *a;
	int i;
	BerElement   *ber;
	struct berval **vals;
  char          *dn;
  printdebug("Filter %s\n",filter);
	rc = ldap_search_ext_s( ldap, BASEDN, LDAP_SCOPE_ONELEVEL, filter, attrs, 0, NULL, NULL, &timeout, 1000, &result );
	if( rc == LDAP_SUCCESS ){
		fprintf(stdout, "Search returned success\n");
		e = ldap_first_entry( ldap, result );
    do{
      if ( e != NULL ) {
        dn = ldap_get_dn( ldap, e );
        fprintf( stdout, "DN: %s\n", dn );
        for ( a = ldap_first_attribute( ldap, e, &ber );
                a != NULL; a = ldap_next_attribute( ldap, e, ber ) ) {
          if ((vals = ldap_get_values_len( ldap, e, a)) != NULL ) {
            for ( i = 0; vals[i] != NULL; i++ ) {
              printf( "%s: %s\n", a, vals[i]->bv_val );
            }
            ldap_value_free_len( vals );
          }
          ldap_memfree( a );
        }
        if ( dn != NULL ){
          ldap_memfree( dn );
        }
        if ( ber != NULL ) {
          ber_free( ber, 0 );
        }
      }
    }while( ( e = ldap_next_entry( ldap, e ) ) );
    ldap_msgfree( result );

	}else{
		WARN( "Search returned error: %s", ldap_err2string( rc ) );
		goto exit;
	}
#if 0
	rc = ldap_compare_ext_s( ldap, bind_user, "givenname", &bv, NULL, NULL );
	if( rc == LDAP_COMPARE_TRUE){
		fprintf( stdout, "Found entry givenname\n" );
	}
#endif
exit:
	if( password ) free( password );
  config_free( config );
	rc = ldap_unbind_ext_s( ldap, NULL, NULL );
	fprintf(stdout, "Unbind returned: %d\n", rc );
	return 0;
}

