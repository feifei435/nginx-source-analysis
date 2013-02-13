
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SLAB_H_INCLUDED_
#define _NGX_SLAB_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_slab_page_s  ngx_slab_page_t;

struct ngx_slab_page_s {
    uintptr_t         slab;
    ngx_slab_page_t  *next;
    uintptr_t         prev;
};


typedef struct {
    ngx_shmtx_sh_t    lock;				//	貌似使用文件锁的情况时，不使用此结构

    size_t            min_size;			//	?????????
    size_t            min_shift;		//	????????

    ngx_slab_page_t  *pages;			//	指向共享内存中pages部分
    ngx_slab_page_t   free;

    u_char           *start;
    u_char           *end;				//	共享内存区域使用的结束

    ngx_shmtx_t       mutex;			//	共享内存使用的互斥对象

    u_char           *log_ctx;			//	???
    u_char            zero;				//	???

    void             *data;				//	e.g. 指向ngx_http_file_cache_sh_t 在函数 ngx_http_file_cache_init（）中设置，指向 file_cache->sh
    void             *addr;				//	共享内存区的开始地址
} ngx_slab_pool_t;


void ngx_slab_init(ngx_slab_pool_t *pool);
void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);
void ngx_slab_free(ngx_slab_pool_t *pool, void *p);
void ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);


#endif /* _NGX_SLAB_H_INCLUDED_ */
