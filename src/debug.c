/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 *
 * debug.c
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
 *
 */
#include "config.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "debug.h"
#if HAVE_SYSLOG_H
#include <syslog.h>
#else
#define LOG_EMERG 0 /* system is unusable */
#define LOG_ALERT 1 /* action must be taken immediately */
#define LOG_CRIT  2 /* critical conditions */
#define LOG_ERR   3 /* error conditions */
#define LOG_WARNING 4 /* warning conditions */
#define LOG_NOTICE  5 /* normal but significant condition */
#define LOG_INFO  6 /* informational */
#define LOG_DEBUG 7 /* debug-level messages */
#endif

typedef struct log_value{
  char   *name;
  int     syslog_val;
} log_value_t;


log_value_t log_values[] = {
  {"EMERG", LOG_EMERG},
  {"ALERT", LOG_ALERT},
  {"CRIT", LOG_CRIT},
  {"ERROR", LOG_ERR},
  {"WARNING", LOG_WARNING},
  {"NOTICE", LOG_NOTICE},
  {"INFO", LOG_INFO},
  {"DEBUG", LOG_DEBUG},
  {NULL, -1}
};


char use_syslog = 0;

void _debug( int level, const char *file, int line, const char *func, const char *fmt, ... ){
  va_list argp;
  if(level){
    fprintf( stderr, "DEBUG: %s:%d %s() ", file, line, func );
    va_start( argp, fmt );
    vfprintf( stderr, fmt, argp );
    va_end( argp );
    fprintf( stderr, "\n" );
  }
}

void _printdebug( int debug, const char *fmt, ... ){
  va_list argp;
  if( !debug ) return;
  fprintf( stderr, "DEBUG: ");
  va_start( argp, fmt );
  vfprintf( stderr, fmt, argp );
  va_end( argp );
}

void _warn( const char *file, int line, const char *func, const char *fmt, ... ){
  va_list argp;
  fprintf( stderr, "WARN: %s:%d %s() ", file, line, func );
  va_start( argp, fmt );
  vfprintf( stderr, fmt, argp );
  va_end( argp );
  fprintf( stderr, "\n" );
}


void _error( const char *file, int line, const char *func, const char *fmt, ... ){
  va_list argp;
  fprintf( stderr, "ERROR: %s:%d %s() ", file, line, func );
  va_start( argp, fmt );
  vfprintf( stderr, fmt, argp );
  va_end( argp );
  fprintf( stderr, "\n" );
}

void _log( int level, const char *fmt, ... ){
  va_list argp;
  char s[BUFSIZ];
  size_t cur_len = 0;
  snprintf(s, BUFSIZ, "LDAP-AUTH: [%s] ", log_values[level].name);
  va_start( argp, fmt );
  cur_len = strlen(s);
  vsnprintf( s+cur_len, BUFSIZ-cur_len, fmt, argp );
  va_end( argp );

#if HAVE_SYSLOG_H
  if (use_syslog)
    syslog(log_values[level].syslog_val, "%s", s);
  else
#endif
  {
    time_t t = time(NULL);
    struct tm tmp;
    localtime_r(&t, &tmp);
    char strtime[26];
    strftime(strtime, 26, "%a %b %e %T %Y", &tmp);
    fprintf( stderr, "%s %s\n", strtime, s);
  }
}



