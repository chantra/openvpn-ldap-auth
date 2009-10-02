
#include "debug.h"
#include "defines.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
#include <sys/types.h>



int
main( int argc, char **argv){
	LDAP		*ldap;
	int ldap_version = 3;
	int ldap_tls_require_cert = LDAP_OPT_X_TLS_HARD;
	int rc;
	char username[] = "uid=chantra,ou=users,dc=example,dc=com";
	char password[] = "foobarcode";
	struct berval bv, *bv2;

	rc = ldap_initialize(&ldap, URI);
	if( rc!= LDAP_SUCCESS ){
		ERROR( "ERROR: ldap_initialize returned (%d) \"%s\" : %s\n", rc, ldap_err2string(rc), strerror(errno) );
		return 1;
	}
	
	rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
	if( rc != LDAP_OPT_SUCCESS ){
		ERROR( "ERROR: ldap_set_option returned (%d) \"%s\"\n", rc, ldap_err2string(rc) );
		return 1;
	}
	
	if( argc == 2 && strcmp( argv[1], "start_tls" ) == 0){
		fprintf( stdout, "Starting TLS\n" );
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
	bv.bv_len = strlen(password);
	bv.bv_val = password;
	bv.bv_len = 0;
	bv.bv_val = NULL;
	fprintf(stderr, "%s", username );

	rc = ldap_sasl_bind_s( ldap, NULL, LDAP_SASL_SIMPLE, &bv, NULL, NULL, &bv2);
	switch( rc ){
		case LDAP_SUCCESS:
			break;
		case LDAP_INVALID_CREDENTIALS:
			WARN( "Invalid credentials" );
			goto exit;
		default:
			WARN( "Unknown return value: %d/0x%2X", rc, rc );
			goto exit;
	}
	if( bv2 ){
		fprintf(stderr, "bv2: %*s\n", (int)bv2->bv_len, bv2->bv_val);
	}
	fprintf(stdout, "Bind returned: %d\n", rc );


	LDAPMessage *e, *result;
	char *attrs[] = {"givenname","ovpnAllow", NULL};
	struct timeval timeout;
	timeout.tv_sec = 15;
	timeout.tv_usec = 0;
	char         *a;
	int i;
	BerElement   *ber;
	struct berval **vals;


	rc = ldap_search_ext_s( ldap, BASEDN, LDAP_SCOPE_ONELEVEL, SEARCH_FILTER, attrs, 0, NULL, NULL, &timeout, 10, &result );
	if( rc == LDAP_SUCCESS ){
		fprintf(stdout, "Search returned success\n");
		e = ldap_first_entry( ldap, result );
		if ( e != NULL ) {
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
			if ( ber != NULL ) {
				ber_free( ber, 0 );
			}
		}
		ldap_msgfree( result );

	}else{
		WARN( "Search returned error: %s", ldap_err2string( rc ) );
		goto exit;
	}
	rc = ldap_compare_ext_s( ldap, username, "givenname", &bv, NULL, NULL );
	if( rc == LDAP_COMPARE_TRUE){
		fprintf( stdout, "Found entry givenname\n" );
	}
exit:
	rc = ldap_unbind_ext_s( ldap, NULL, NULL );
	fprintf(stdout, "Unbind returned: %d\n", rc );

	return 0;
}

