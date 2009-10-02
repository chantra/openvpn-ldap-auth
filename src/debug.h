/* vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab
*/
#ifndef _DEBUG_H_
#define _DEBUG_H_



#define DEBUG_SQL 0
#define DEBUG_USER 0
#define DEBUG_MAIN 1


void _warn( const char *file, int line, const char *func, const char *fmt, ... );
#define WARN( fmt, args... ) _warn( __FILE__, __LINE__, __FUNCTION__, fmt, ##args )

void _error( const char *file, int line, const char *func, const char *fmt, ... );
#define ERROR( fmt, args... ) _error( __FILE__, __LINE__, __FUNCTION__, fmt, ##args )


void _debug( int level, const char *file, int line, const char *func, const char *fmt, ... );
#define DEBUG( level, fmt, args... ) _debug( level, __FILE__, __LINE__, __FUNCTION__, fmt, ##args )

#endif /* _DEBUG_H_ */

