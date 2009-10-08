#ACLOCAL_AMFLAGS = -I m4 $(ACLOCAL_AMFLAGS)

INCLUDES = -I$(top_srcdir)/src
AM_LDFLAGS = -L$(top_srcdir)/src

bin_PROGRAMS = testplugin

testplugin_SOURCES = testplugin.c

ldadd = $(top_srcdir)/src/openvpn-auth-ldap.a

#testplugin_LDADD = $(ldadd)
testplugin_LDADD = -lopenvpn-auth-ldap
