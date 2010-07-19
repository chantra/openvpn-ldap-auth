#ACLOCAL_AMFLAGS = -I m4 $(ACLOCAL_AMFLAGS)
#bin_PROGRAMS = openvpn-ldap-rules
#lib_LIBRARIES = libopenvpn-ldap-auth.a
lib_LTLIBRARIES = libopenvpn-ldap-auth.la

auth_ldap_SOURCES = utils.h utils.c \
							cnf.h cnf.c \
							list.h list.c \
							action.h action.c \
							la_ldap.h la_ldap.c \
							ldap_profile.h ldap_profile.c \
							debug.h debug.c

#openvpn_ldap_rules_SOURCES = openvpn-ldap-rules.c \
#					$(auth_ldap_SOURCES)

#libopenvpn_ldap_auth_a_SOURCES = ldap-auth.c \
#				$(auth_ldap_SOURCES)

libopenvpn_ldap_auth_la_SOURCES = ldap-auth.c \
				$(auth_ldap_SOURCES)

#libopenvpn_auth_ldap_la_LDFLAGS =  -export-dynamic $(LDFLAGS)



