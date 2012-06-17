
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

struct ngx_list_part_s {
    void             *elts;					/* [analy]   指向该节点实际的数据区(该数据区中可以存放nalloc个大小为size的元素) */
    ngx_uint_t        nelts;				/* [analy]   实际存放的元素个数   */
    ngx_list_part_t  *next;					/* [analy]   指向下一个节点		 */
};


typedef struct {
    ngx_list_part_t  *last;					/* [analy]   指向链表的最后一个节点	*/
    ngx_list_part_t   part;					/* [analy]   链表头中包含的第一个节点*/
    size_t            size;					/* [analy]   元素的大小				*/
    ngx_uint_t        nalloc;				/* [analy]   链表中分配的元素个数	*/
    ngx_pool_t       *pool;					/* [analy]   链表使用的内存池		*/
} ngx_list_t;


ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
