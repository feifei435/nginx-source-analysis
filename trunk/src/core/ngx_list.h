
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
    void             *elts;					/* [analysis]   ָ��ýڵ�ʵ�ʵ�������(���������п��Դ��nalloc����СΪsize��Ԫ��) */
    ngx_uint_t        nelts;				/* [analysis]   ʵ�ʴ�ŵ�Ԫ�ظ���   */
    ngx_list_part_t  *next;					/* [analysis]   ָ����һ���ڵ�		 */
};


typedef struct {
    ngx_list_part_t  *last;					/* [analysis]   ָ����������һ���ڵ�	*/
    ngx_list_part_t   part;					/* [analysis]   ����ͷ�а����ĵ�һ���ڵ�*/
    size_t            size;					/* [analysis]   Ԫ�صĴ�С				*/
    ngx_uint_t        nalloc;				/* [analysis]   �����з����Ԫ�ظ���	*/
    ngx_pool_t       *pool;					/* [analysis]   ����ʹ�õ��ڴ��		*/
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
