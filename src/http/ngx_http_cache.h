
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CACHE_H_INCLUDED_
#define _NGX_HTTP_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_CACHE_MISS          1				//	缓存未命中
#define NGX_HTTP_CACHE_BYPASS        2				//	不在缓存获取到后端服务器获取响应
#define NGX_HTTP_CACHE_EXPIRED       3
#define NGX_HTTP_CACHE_STALE         4
#define NGX_HTTP_CACHE_UPDATING      5
#define NGX_HTTP_CACHE_HIT           6				//	缓存命中
#define NGX_HTTP_CACHE_SCARCE        7

#define NGX_HTTP_CACHE_KEY_LEN       16


typedef struct {
    ngx_uint_t                       status;
    time_t                           valid;
} ngx_http_cache_valid_t;


typedef struct {
    ngx_rbtree_node_t                node;
    ngx_queue_t                      queue;

    u_char                           key[NGX_HTTP_CACHE_KEY_LEN			//	保存文件名的后12个字节
                                         - sizeof(ngx_rbtree_key_t)];

    unsigned                         count:20;					//	引用计数？？？？？？？
    unsigned                         uses:10;					//	缓存文件被多少请求在使用
    unsigned                         valid_msec:10;
    unsigned                         error:10;					//	????
    unsigned                         exists:1;					//	存在对应的cache文件；ngx_http_file_cache_add()设置
    unsigned                         updating:1;
    unsigned                         deleting:1;
                                     /* 11 unused bits */

    ngx_file_uniq_t                  uniq;
    time_t                           expire;					//	缓存文件的失效时间
    time_t                           valid_sec;
    size_t                           body_start;
    off_t                            fs_size;
} ngx_http_file_cache_node_t;


struct ngx_http_cache_s {
    ngx_file_t                       file;								//	???
    ngx_array_t                      keys;
    uint32_t                         crc32;
    u_char                           key[NGX_HTTP_CACHE_KEY_LEN];		//	在函数 ngx_http_file_cache_create_key（）中设置

    ngx_file_uniq_t                  uniq;
    time_t                           valid_sec;
    time_t                           last_modified;
    time_t                           date;

    size_t                           header_start;				//	cache文件头部自定义的数据；ngx_http_file_cache_create_key（）函数中创建
    size_t                           body_start;				//	u->conf->buffer_size; 接收后端服务器反馈数据缓冲区的大小
    off_t                            length;					//	????
    off_t                            fs_size;					//	在函数 ngx_http_file_cache_add_file（）中设置

    ngx_uint_t                       min_uses;					//	u->conf->cache_min_uses, proxy模块使用指令 "proxy_cache_min_uses" 指定
    ngx_uint_t                       error;						//	函数中 ngx_http_upstream_finalize_request（）设置
    ngx_uint_t                       valid_msec;

    ngx_buf_t                       *buf;						//	函数 ngx_http_file_cache_ope（）中创建

    ngx_http_file_cache_t           *file_cache;				//	ngx_http_upstream_cache()函数中设置；
    ngx_http_file_cache_node_t      *node;						//	ngx_http_file_cache_exists（）函数中设置

    ngx_msec_t                       lock_timeout;				//	u->conf->cache_lock_timeout, proxy模块使用指令 "proxy_cache_lock_timeout" 指定
    ngx_msec_t                       wait_time;

    ngx_event_t                      wait_event;

    unsigned                         lock:1;					//	u->conf->cache_lock, proxy模块使用指令 "proxy_cache_lock" 指定
    unsigned                         waiting:1;					//	???

    unsigned                         updated:1;					//	???
    unsigned                         updating:1;
    unsigned                         exists:1;
    unsigned                         temp_file:1;
};


typedef struct {
    time_t                           valid_sec;
    time_t                           last_modified;
    time_t                           date;
    uint32_t                         crc32;
    u_short                          valid_msec;
    u_short                          header_start;
    u_short                          body_start;
} ngx_http_file_cache_header_t;


typedef struct {
    ngx_rbtree_t                     rbtree;
    ngx_rbtree_node_t                sentinel;
    ngx_queue_t                      queue;
    ngx_atomic_t                     cold;
    ngx_atomic_t                     loading;
    off_t                            size;
} ngx_http_file_cache_sh_t;


struct ngx_http_file_cache_s {
    ngx_http_file_cache_sh_t        *sh;							//	在函数 ngx_http_file_cache_init（）中设置
    ngx_slab_pool_t                 *shpool;						//	在函数 ngx_http_file_cache_init（）中设置

    ngx_path_t                      *path;							//	cache的路径，在函数中 ngx_http_file_cache_set_slot（）设置

    off_t                            max_size;						//	当前cache占用多少个文件系统块；（cache磁盘的最大空间，通过指令在配置文件中指定；在函数中 ngx_http_file_cache_set_slot（）设置）
    size_t                           bsize;							//	文件系统每块大小；在函数 ngx_http_file_cache_init（）中设置

    time_t                           inactive;						//	不活跃时间，多久不使用就被删除；在函数中 ngx_http_file_cache_set_slot（）设置

    ngx_uint_t                       files;							//	当前有多少个cache文件, 启动时被loader进程设置。（在函数 ngx_http_file_cache_manage_file()中设置）
    ngx_uint_t                       loader_files;					//	默认100，在函数中 ngx_http_file_cache_set_slot（）设置
    ngx_msec_t                       last;							//	最后被manage或者loader访问的时间（在函数 ngx_http_file_cache_manager()中设置 ）
    ngx_msec_t                       loader_sleep;					//	默认50，在函数中 ngx_http_file_cache_set_slot（）设置 
    ngx_msec_t                       loader_threshold;				//	默认200，在函数中 ngx_http_file_cache_set_slot（）设置

    ngx_shm_zone_t                  *shm_zone;						//	在函数中 ngx_http_file_cache_set_slot（）设置
};


ngx_int_t ngx_http_file_cache_new(ngx_http_request_t *r);
ngx_int_t ngx_http_file_cache_create(ngx_http_request_t *r);
void ngx_http_file_cache_create_key(ngx_http_request_t *r);
ngx_int_t ngx_http_file_cache_open(ngx_http_request_t *r);
void ngx_http_file_cache_set_header(ngx_http_request_t *r, u_char *buf);
void ngx_http_file_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf);
ngx_int_t ngx_http_cache_send(ngx_http_request_t *);
void ngx_http_file_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf);
time_t ngx_http_file_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status);

char *ngx_http_file_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_file_cache_valid_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


extern ngx_str_t  ngx_http_cache_status[];


#endif /* _NGX_HTTP_CACHE_H_INCLUDED_ */
