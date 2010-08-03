/**
 * list.c
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

#include "list.h"
#include "utils.h"
#include "debug.h"

/**
 * list_item_new
 */
list_item_t *
list_item_new( void ){
  list_item_t *i = la_malloc( sizeof( list_item_t ) );
  if( i )
    la_memset( i, 0, sizeof( list_item_t ) );
  return i;
}

/**
 * list_new
 */
list_t *
list_new( void ){
  list_t *l = NULL;
  l = la_malloc( sizeof( list_t ) );
  if( l )
    la_memset( l, 0, sizeof( list_t ) );
  return l;
}

/**
 * list_free
 */
void
list_free( list_t *l, void (*item_free_func)( void *data ) ){
  list_item_t *i, *cur;
  if( !l ) return;
  i = l->first;
  while( i ){
    cur = i;
    i = i->next;
    if( item_free_func ) item_free_func( cur->data );
    la_free( cur );
  }
  la_free( l );

}

/**
 * list_free_item
 */
void
list_free_item( list_t *l, list_item_t *i, void (*item_free_func)( void *data ) ){

  if( l->counter == 0 ) return;
  if( l->first == i ) l->first = i->next;
  if( l->last == i ) l->last = i->prev;
  if( i->next ) i->next->prev = i->prev;
  if( i->prev ) i->prev->next = i->next;
  if( item_free_func ) item_free_func( i->data );
  la_free( i );
  l->counter--;
}

/**
 * list_remove_item
 * Remove an item from the list. The item cell is freed
 * BUT the item data is not freed
 * The caller will need to free it, or memory will be lost
 */
void *
list_remove_item( list_t *l, list_item_t *i ){
  void *data = NULL;
  if( !i ) return NULL;
  data = i->data;
  list_free_item( l, i, NULL );
  return data;
}
/**
 * list_remove_item_at
 *
 */

void *
list_remove_item_at( list_t *l, uint32_t index ){
  list_item_t *i;
  i = list_item_at(l, index );
  if( !i ) return NULL;
  return list_remove_item( l, i );
}

/**
 * list_item_at
 */
list_item_t *
list_item_at( list_t *l, uint32_t index ){
  list_item_t *it = NULL;
  uint32_t i = 0;
  if( !l || index < 0 || index >= l->counter ) return NULL;
  it = list_first( l );
  if( !it ) return NULL;
  for( ; i < index && it ; i++ ){
    it = it->next;
  }
  return it;
}

/**
 * list_append
 */
list_item_t *
list_append( list_t *l, void *data ){
  list_item_t *i = list_item_new( );
  if( !i ) return NULL;
  i->data = data;
  if( l->counter == 0 ){
    l->first = l->last = i;
  }else{
    if( l->last ){
      l->last->next = i;
      i->prev = l->last;
      l->last = i;
    }else{
      ERROR("Appending to list with elements, but last is not set" );
    }
  }
  l->counter++;
  return i;
}

/**
 * list_prepend
 */

list_item_t *
list_prepend( list_t *l, void *data ){
  list_item_t *i = list_item_new( );
  if( !i ) return NULL;
  i->data = data;
  if( l->counter == 0 ){
    l->first = l->last = i;
  }else{
    if( l->first ){
      l->first->prev = i;
      i->next = l->first;
      l->first = i;
    }else{
      ERROR("Prepending to list with elements, but first is not set" );
    }
  }
  l->counter++;
  return i;
}


/**
 * list_length
 */
uint32_t
list_length( list_t *l ){
  if( l ) return l->counter;
  return 0;
}

/**
 * list_first
 */
list_item_t *
list_first( list_t *l ){
  if( l ) return l->first;
  return NULL;
}

/**
 * list_last
 */
list_item_t *
list_last( list_t *l ){
  if( l ) return l->last;
  return NULL;
}


/**
 * list_item_next
 */

list_item_t *
list_item_next( list_item_t *i ){
  if( i ) return i->next;
  return NULL;
}

/**
 * list_item_prev
 */

list_item_t *
list_item_prev( list_item_t *i ){
  if( i ) return i->prev;
  return NULL;
}

