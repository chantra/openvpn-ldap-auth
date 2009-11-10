/**
 * list.h
 * vim: tabstop=2 softtabstop=2 shiftwidth=2 expandtab
 * Copyright (C) 2009 Emmanuel Bretelle <chantra@debuntu.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __LIST_H__
#define __LIST_H__

#include <stdint.h>

typedef struct list_item{
  void              *data;
  struct list_item  *prev;
  struct list_item  *next;
} list_item_t;

typedef struct list {
  list_item_t *first;
  list_item_t *last;
  uint32_t    counter;
} list_t;

extern list_t       *list_new( void );
extern void         list_free( list_t *l, void (*item_free_func)( void *data ) );
extern void         list_free_item( list_t *l, list_item_t *i, void (*item_free_func)( void *data ) );
extern void         *list_remove_item( list_t *l, list_item_t *i );
extern void         *list_remove_item_at( list_t *l, uint32_t index );
extern list_item_t  *list_item_at( list_t *l, uint32_t index );

extern list_item_t  *list_append( list_t *l, void *data );
extern list_item_t  *list_prepend( list_t *l, void *data );
extern uint32_t     list_length( list_t *l );
extern list_item_t  *list_first( list_t *l );
extern list_item_t  *list_last( list_t *l );

extern list_item_t  *list_item_next( list_item_t *i );
extern list_item_t  *list_item_prev( list_item_t *i );

#endif /* __LIST_H__ */

