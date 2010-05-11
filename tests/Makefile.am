#ACLOCAL_AMFLAGS = -I m4 $(ACLOCAL_AMFLAGS)

INCLUDES = -I$(top_srcdir)/src
AM_LDFLAGS = -L$(top_srcdir)/src

bin_PROGRAMS = testplugin openvpn-ldap-search

testplugin_SOURCES = testplugin.c
openvpn_ldap_search_SOURCES = openvpn-ldap-search.c

#ldadd = $(top_srcdir)/src/openvpn-ldap-auth.a

#testplugin_LDADD = $(ldadd)
testplugin_LDADD = -lopenvpn-ldap-auth
openvpn_ldap_search_LDADD = -lopenvpn-ldap-auth
