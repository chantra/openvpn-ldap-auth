#ACLOCAL_AMFLAGS = -I m4 $(ACLOCAL_AMFLAGS)
#bin_PROGRAMS = openvpn-ldap-rules
#lib_LIBRARIES = openvpn-auth-ldap.a
lib_LTLIBRARIES = libopenvpn-auth-ldap.la

auth_ldap_SOURCES = utils.h utils.c \
							cnf.h cnf.c \
							list.h list.c \
							debug.h debug.c

#openvpn_ldap_rules_SOURCES = openvpn-ldap-rules.c \
#					$(auth_ldap_SOURCES)

#openvpn_auth_ldap_a_SOURCES = auth-ldap.c \
#				$(auth_ldap_SOURCES)

libopenvpn_auth_ldap_la_SOURCES = auth-ldap.c \
				$(auth_ldap_SOURCES)

#libopenvpn_auth_ldap_la_LDFLAGS =  -export-dynamic $(LDFLAGS)

#SUIDMODE = -o root -m 4755

#install-data-hook:
#	-$(INSTALL_PROGRAM) $(bin_PROGRAMS) $(SUIDMODE) $(DESTDIR)$(bindir)/openvpnstats-snmp

