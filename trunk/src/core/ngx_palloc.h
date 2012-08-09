
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;					/* [analy]	清理函数 */	
    void                 *data;						/* [analy]	需要清除的数据 */	
    ngx_pool_cleanup_t   *next;						/* [analy]	下一个cleanup callback */
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t     *next;
    void                 *alloc;
};

/* 
 * [analy]	
 * 内存池的数据块位置信息
 */
typedef struct {
    u_char               *last;						/* [analy]	当前内存池分配到此处，即下一次分配从此处开始 */
    u_char               *end;						/* [analy]	内存池结束位置 */
    ngx_pool_t           *next;						/* [analy]	内存池里面有很多块内存，这些内存块就是通过该指针连成链表的 */
    ngx_uint_t            failed;					/* [analy]	内存池分配失败次数 */
} ngx_pool_data_t;

/* 
 * [analy]	
 * 内存池头部结构
 */
struct ngx_pool_s {
    ngx_pool_data_t       d;						/* [analy]	内存池中的数据块 */
    size_t                max;						/* [analy]	数据块的大小，即可分配的内存的最大值 */
    ngx_pool_t           *current;					/* [analy]	指向当前内存池 */
    ngx_chain_t          *chain;					/* [analy]	挂接一个ngx_chain_t结构链表，此链表应为废弃的不用的；在宏 ngx_free_chain（）函数中添加的 */
    ngx_pool_large_t     *large;					/* [analy]	大块内存链表，即分配空间超过max的内存 */
    ngx_pool_cleanup_t   *cleanup;					/* [analy]	释放内存池的callback */
    ngx_log_t            *log;						/* [analy]	日志信息 */
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;


void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_calloc(size_t size, ngx_log_t *log);

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
