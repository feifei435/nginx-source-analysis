
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_OPEN_FILE_CACHE_H_INCLUDED_
#define _NGX_OPEN_FILE_CACHE_H_INCLUDED_


#define NGX_OPEN_FILE_DIRECTIO_OFF  NGX_MAX_OFF_T_VALUE

//	用于保存打开文件的信息
typedef struct {
    ngx_fd_t                 fd;					//	文件描述符，如果打开的是目录或者调用类stat函数失败都将设置为 NGX_INVALID_FILE；
    ngx_file_uniq_t          uniq;					//	i节点编号
    time_t                   mtime;					//	最后修改时间
    off_t                    size;					//	文件大小
    off_t                    fs_size;				//	占用文件系统的大小
    off_t                    directio;				//	对应 "directio" 指令设置的大小
    size_t                   read_ahead;			//	对应 "read_ahead" 指令设置的大小

    ngx_err_t                err;					//	errno(模块中open和stat文件时的错误码)
    char                    *failed;				//	失败原因

    time_t                   valid;					//	指定了多长时间需要检查cache中的缓存项目的有效信息，默认是60s；对应指令 "open_file_cache_valid" 指定的时间

    ngx_uint_t               min_uses;				//	指定cache最小使用的次数，默认是1次；对应指令 "open_file_cache_min_uses" 设置
	
#if (NGX_HAVE_OPENAT)
    size_t                   disable_symlinks_from;
    unsigned                 disable_symlinks:2;
#endif

    unsigned                 test_dir:1;
    unsigned                 test_only:1;
    unsigned                 log:1;					//	是否为log文件？？？
    unsigned                 errors:1;				//	指定是否在搜索一个文件时记录cache错误，默认是关闭状态；对应指令 "open_file_cache_errors" 设置
    unsigned                 events:1;

    unsigned                 is_dir:1;				//	是否为目录
    unsigned                 is_file:1;				//	是否为文件
    unsigned                 is_link:1;				//	是否为链接
    unsigned                 is_exec:1;				//	是否可执行
    unsigned                 is_directio:1;
} ngx_open_file_info_t;


typedef struct ngx_cached_open_file_s  ngx_cached_open_file_t;

//	与单个文件缓存相关
struct ngx_cached_open_file_s {
    ngx_rbtree_node_t        node;
    ngx_queue_t              queue;

    u_char                  *name;							//	被缓存文件的名称(ngx_open_cached_file()函数中设置)
    time_t                   created;						//	创建或更新的时间
    time_t                   accessed;						//	访问的时间

    ngx_fd_t                 fd;							//	文件描述符fd
    ngx_file_uniq_t          uniq;							//	i节点编号
    time_t                   mtime;							//	最后修改时间
    off_t                    size;							//	文件大小
    ngx_err_t                err;							//	errno(在open()和stat()失败的情况时会设置错误码)

    uint32_t                 uses;							//	缓存的使用次数

#if (NGX_HAVE_OPENAT)
    size_t                   disable_symlinks_from;				
    unsigned                 disable_symlinks:2;				
#endif

    unsigned                 count:24;						//	文件的引用计数，表示现在文件被几个请求使用中
    unsigned                 close:1;						//	表示文件是否需要被关闭
    unsigned                 use_event:1;

    unsigned                 is_dir:1;						//	是否为目录
    unsigned                 is_file:1;						//	是否为文件
    unsigned                 is_link:1;						//	是否为链接
    unsigned                 is_exec:1;						//	是否可执行
    unsigned                 is_directio:1;

    ngx_event_t             *event;
};

//	文件缓存表；管理所有缓存文件的结构
typedef struct {
    ngx_rbtree_t             rbtree;
    ngx_rbtree_node_t        sentinel;
    ngx_queue_t              expire_queue;

    ngx_uint_t               current;				//	当前cache的文件个数；初始值为0
    ngx_uint_t               max;					//	指令 "open_file_cache"的max参数指定的cache文件个数 (ngx_open_file_cache_init()函数中设置)
    time_t                   inactive;				//	指令 "open_file_cache"的inactive参数指定的时间 (ngx_open_file_cache_init()函数中设置)
} ngx_open_file_cache_t;


typedef struct {
    ngx_open_file_cache_t   *cache;					//	使用的cache
    ngx_cached_open_file_t  *file;					//	对应的cache文件
    ngx_uint_t               min_uses;				//	设置日志最小使用次数
    ngx_log_t               *log;					//	使用的日志指针
} ngx_open_file_cache_cleanup_t;


typedef struct {

    /* ngx_connection_t stub to allow use c->fd as event ident */
    void                    *data;
    ngx_event_t             *read;
    ngx_event_t             *write;
    ngx_fd_t                 fd;

    ngx_cached_open_file_t  *file;
    ngx_open_file_cache_t   *cache;
} ngx_open_file_cache_event_t;


ngx_open_file_cache_t *ngx_open_file_cache_init(ngx_pool_t *pool,
    ngx_uint_t max, time_t inactive);
ngx_int_t ngx_open_cached_file(ngx_open_file_cache_t *cache, ngx_str_t *name,
    ngx_open_file_info_t *of, ngx_pool_t *pool);


#endif /* _NGX_OPEN_FILE_CACHE_H_INCLUDED_ */
