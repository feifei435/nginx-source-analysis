
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

struct ngx_buf_s {
    u_char          *pos;			//	暂时理解为 已经解析完数据的末尾指针
    u_char          *last;			//	暂时理解为 读到的数据末尾指针(即缓冲区中已经存在数据)
    off_t            file_pos;		//	如果数据在文件里，标识在文件中的当前位置
    off_t            file_last;		//	如果数据在文件里，标识在文件中的结尾位置

    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    ngx_buf_tag_t    tag;
    ngx_file_t      *file;			//	对应文件结构指针
    ngx_buf_t       *shadow;


    /* the buf's content could be changed */
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1;			//	是否在内存中

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;			//	内存中的文件映射

    unsigned         recycled:1;		//	被回收
    unsigned         in_file:1;			//	文件缓冲(标识要发送的数据在文件中)
    unsigned         flush:1;			//	被清除
    unsigned         sync:1;			//	异步
    unsigned         last_buf:1;		//	此字段是一个位域，设为1表示此缓冲区是链表中最后一个元素，设置为0说明后边还有元素
    unsigned         last_in_chain:1;	//	链表的尾部

    unsigned         last_shadow:1;
    unsigned         temp_file:1;		//	是否是临时文件中的缓冲

    /* STUB */ int   num;
};

//	buffer链
struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};

//	缓冲区尺寸大小
typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

#if (NGX_HAVE_FILE_AIO)
typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);
#endif


/* 
 *	[analy] 主要是管理输出buf 
 */
struct ngx_output_chain_ctx_s {			
    ngx_buf_t                   *buf;		//	这个域也就是我们拷贝数据的地方，我们一般输出的话都是从in直接copy相应的size到buf中
    ngx_chain_t                 *in;		//	这个就是我们保存那些需要发送数据的地方
    ngx_chain_t                 *free;		//	这个保存了一些空的buf，也就是说如果free存在，我们都会直接从free中取buf到前面的buf域
    ngx_chain_t                 *busy;		//	这个保存了已经发送完毕的buf，也就是每次我们从in中将buf读取完毕后，确定数据已经取完，
											//	此时就会将这个chain拷贝到busy中。然后将比较老的busy buf拷贝到free中

	//	是否使用sendfile，是否使用directio等等
    unsigned                     sendfile:1;	//	ngx_http_copy_filter()函数中根据c->sendfile来设置
    unsigned                     directio:1;
#if (NGX_HAVE_ALIGNED_DIRECTIO)
    unsigned                     unaligned:1;
#endif
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
#if (NGX_HAVE_FILE_AIO)
    unsigned                     aio:1;

    ngx_output_chain_aio_pt      aio_handler;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;			//	每次从pool中重新alloc一个buf这个值都会相应加一  
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;				//	这个用来标记当前那个模块使用这个chain  

    ngx_output_chain_filter_pt   output_filter;		//	一个回调函数，用来过滤输出
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;					/* [analy] 这个主要是用在upstream模块 */


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);

/* 
 *	[analy] 挂载cl到pool->chain的单向循环链表上，顺序是按照后释放在前的原则
 */
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);


#endif /* _NGX_BUF_H_INCLUDED_ */
