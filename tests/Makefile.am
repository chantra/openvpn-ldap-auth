#ACLOCAL_AMFLAGS = -I m4 $(ACLOCAL_AMFLAGS)

INCLUDES = -I$(top_srcdir)/src
AM_LDFLAGS = -L$(top_srcdir)/src

noinst_PROGRAMS = openvpn-ldap-search
bin_PROGRAMS = openvpn-ldap-auth-test

openvpn_ldap_auth_test_SOURCES = openvpn-ldap-auth-test.c
openvpn_ldap_search_SOURCES = openvpn-ldap-search.c

ldadd = $(top_srcdir)/src/.libs/libopenvpn-ldap-auth.a

openvpn_ldap_auth_test_LDADD = $(ldadd)
#testplugin_LDADD = -lopenvpn-ldap-auth
openvpn_ldap_search_LDADD = -lopenvpn-ldap-auth

