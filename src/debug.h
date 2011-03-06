/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * debug.h
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

#ifndef _DEBUG_H_
#define _DEBUG_H_


extern char use_syslog;

#define D_EMERG 0 /* system is unusable */
#define D_ALERT 1 /* action must be taken immediately */
#define D_CRIT  2 /* critical conditions */
#define D_ERR   3 /* error conditions */
#define D_WARNING 4 /* warning conditions */
#define D_NOTICE  5 /* normal but significant condition */
#define D_INFO  6 /* informational */
#define D_DEBUG 7 /* debug-level messages */

#define DONOTICE(verb) ((verb) >= 4)
#define DOINFO(verb) ((verb) >= 5)
#define DODEBUG(verb) ((verb) >= 6)


void _printdebug( int debug, const char *fmt, ... );

void _warn( const char *file, int line, const char *func, const char *fmt, ... );
#define WARN( fmt, args... ) _warn( __FILE__, __LINE__, __FUNCTION__, fmt, ##args )

void _error( const char *file, int line, const char *func, const char *fmt, ... );
#define ERROR( fmt, args... ) _error( __FILE__, __LINE__, __FUNCTION__, fmt, ##args )

void _debug( int level, const char *file, int line, const char *func, const char *fmt, ... );
#define DEBUG( level, fmt, args... ) _debug( level, __FILE__, __LINE__, __FUNCTION__, fmt, ##args )

void _log( int level, const char *fmt, ... );


#define LOGEMERG( fmt, args... ) _log( D_EMERG, fmt, ##args )

#define LOGALERT( fmt, args... ) _log( D_ALERT, fmt, ##args )

#define LOGCRIT( fmt, args... ) _log( D_CRIT, fmt, ##args )

#define LOGERROR( fmt, args... ) _log( D_ERR, fmt, ##args )

#define LOGWARNING( fmt, args... ) _log( D_WARNING, fmt, ##args )

#define LOGNOTICE( fmt, args... ) _log( D_NOTICE, fmt, ##args )

#define LOGINFO( fmt, args... ) _log( D_INFO, fmt, ##args )

#define LOGDEBUG( fmt, args... ) _log( D_DEBUG, fmt, ##args )

#endif /* _DEBUG_H_ */

