/* vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab
*/
#include <stdarg.h>
#include <stdio.h>

#include "debug.h"

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


