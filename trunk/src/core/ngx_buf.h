
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
    u_char          *pos;			//	��ʱ���Ϊ �Ѿ����������ݵ�ĩβָ��
    u_char          *last;			//	��ʱ���Ϊ ����������ĩβָ��(�����������Ѿ���������)
    off_t            file_pos;		//	����������ļ����ʶ���ļ��еĵ�ǰλ��
    off_t            file_last;		//	����������ļ����ʶ���ļ��еĽ�βλ��

    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    ngx_buf_tag_t    tag;
    ngx_file_t      *file;			//	��Ӧ�ļ��ṹָ��
    ngx_buf_t       *shadow;


    /* the buf's content could be changed */
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1;			//	�Ƿ����ڴ���

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;			//	�ڴ��е��ļ�ӳ��

    unsigned         recycled:1;		//	������
    unsigned         in_file:1;			//	�ļ�����(��ʶҪ���͵��������ļ���)
    unsigned         flush:1;			//	�����
    unsigned         sync:1;			//	�첽
    unsigned         last_buf:1;		//	���ֶ���һ��λ����Ϊ1��ʾ�˻����������������һ��Ԫ�أ�����Ϊ0˵����߻���Ԫ��
    unsigned         last_in_chain:1;	//	�����β��

    unsigned         last_shadow:1;
    unsigned         temp_file:1;		//	�Ƿ�����ʱ�ļ��еĻ���

    /* STUB */ int   num;
};

//	buffer��
struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};

//	�������ߴ��С
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
 *	[analy] ��Ҫ�ǹ������buf 
 */
struct ngx_output_chain_ctx_s {			
    ngx_buf_t                   *buf;		//	�����Ҳ�������ǿ������ݵĵط�������һ������Ļ����Ǵ�inֱ��copy��Ӧ��size��buf��
    ngx_chain_t                 *in;		//	����������Ǳ�����Щ��Ҫ�������ݵĵط�
    ngx_chain_t                 *free;		//	���������һЩ�յ�buf��Ҳ����˵���free���ڣ����Ƕ���ֱ�Ӵ�free��ȡbuf��ǰ���buf��
    ngx_chain_t                 *busy;		//	����������Ѿ�������ϵ�buf��Ҳ����ÿ�����Ǵ�in�н�buf��ȡ��Ϻ�ȷ�������Ѿ�ȡ�꣬
											//	��ʱ�ͻὫ���chain������busy�С�Ȼ�󽫱Ƚ��ϵ�busy buf������free��

	//	�Ƿ�ʹ��sendfile���Ƿ�ʹ��directio�ȵ�
    unsigned                     sendfile:1;	//	ngx_http_copy_filter()�����и���c->sendfile������
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
    ngx_int_t                    allocated;			//	ÿ�δ�pool������allocһ��buf���ֵ������Ӧ��һ  
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;				//	���������ǵ�ǰ�Ǹ�ģ��ʹ�����chain  

    ngx_output_chain_filter_pt   output_filter;		//	һ���ص������������������
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;					/* [analy] �����Ҫ������upstreamģ�� */


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
 *	[analy] ����cl��pool->chain�ĵ���ѭ�������ϣ�˳���ǰ��պ��ͷ���ǰ��ԭ��
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
