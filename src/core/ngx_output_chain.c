
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if 0
#define NGX_SENDFILE_LIMIT  4096
#endif

/*
 * When DIRECTIO is enabled FreeBSD, Solaris, and MacOSX read directly
 * to an application memory from a device if parameters are aligned
 * to device sector boundary (512 bytes).  They fallback to usual read
 * operation if the parameters are not aligned.
 * Linux allows DIRECTIO only if the parameters are aligned to a filesystem
 * sector boundary, otherwise it returns EINVAL.  The sector size is
 * usually 512 bytes, however, on XFS it may be 4096 bytes.
 */

#define NGX_NONE            1


static ngx_inline ngx_int_t
    ngx_output_chain_as_is(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf);
static ngx_int_t ngx_output_chain_add_copy(ngx_pool_t *pool,
    ngx_chain_t **chain, ngx_chain_t *in);
static ngx_int_t ngx_output_chain_align_file_buf(ngx_output_chain_ctx_t *ctx,
    off_t bsize);
static ngx_int_t ngx_output_chain_get_buf(ngx_output_chain_ctx_t *ctx,
    off_t bsize);
static ngx_int_t ngx_output_chain_copy_buf(ngx_output_chain_ctx_t *ctx);


/*
 *	NGX_ERROR		发送出错
 *	NGX_OK			已发送完毕
 *	NGX_AGAIN		未发送完，稍后将重试
 *	NGX_DONE		
 */
ngx_int_t
ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in)
{
    off_t         bsize;
    ngx_int_t     rc, last;
    ngx_chain_t  *cl, *out, **last_out;

    if (ctx->in == NULL && ctx->busy == NULL) {

        /*
         * the short path for the case when the ctx->in and ctx->busy chains
         * are empty, the incoming chain is empty too or has the single buf
         * that does not require the copy
         */

        if (in == NULL) {
            return ctx->output_filter(ctx->filter_ctx, in);				//	ngx_http_next_filter 或 ngx_chain_writer
        }

        if (in->next == NULL

#if (NGX_SENDFILE_LIMIT)			//	此宏貌似没有定义
            && !(in->buf->in_file && in->buf->file_last > NGX_SENDFILE_LIMIT)
#endif
		
            && ngx_output_chain_as_is(ctx, in->buf))		//	检查是否需要合并buf
        {
            return ctx->output_filter(ctx->filter_ctx, in);
        }
    }

    /* add the incoming buf to the chain ctx->in */
    if (in) {
        if (ngx_output_chain_add_copy(ctx->pool, &ctx->in, in) == NGX_ERROR) {			//	将in中的数据拼接到ctx->in尾部
            return NGX_ERROR;
        }
    }

    out = NULL;
    last_out = &out;					//	设置out为准备输出的chain，下边将会对last_out进行赋值
    last = NGX_NONE;

    for ( ;; ) {

#if (NGX_HAVE_FILE_AIO)
        if (ctx->aio) {
            return NGX_AGAIN;
        }
#endif

		//	循环处理ctx->in中的数据, 处理完后将把数据挂载到以out为首的chain链上。
        while (ctx->in) {

            /*
             * cycle while there are the ctx->in bufs
             * and there are the free output bufs to copy in
             */

            bsize = ngx_buf_size(ctx->in->buf);

			//	buf等于0，并且不是特殊buf，说明有BUG需要debug
            if (bsize == 0 && !ngx_buf_special(ctx->in->buf)) {

                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                              "zero size buf in output "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              ctx->in->buf->temporary,
                              ctx->in->buf->recycled,
                              ctx->in->buf->in_file,
                              ctx->in->buf->start,
                              ctx->in->buf->pos,
                              ctx->in->buf->last,
                              ctx->in->buf->file,
                              ctx->in->buf->file_pos,
                              ctx->in->buf->file_last);

                ngx_debug_point();

                ctx->in = ctx->in->next;			//	继续查看下一个

                continue;
            }

			//	检查是否需要复制buf，返回1说明不需要拷贝
            if (ngx_output_chain_as_is(ctx, ctx->in->buf)) {

                /* move the chain link to the output chain */

				//	不需要拷贝时, 检查chain链中的下一个
                cl = ctx->in;
                ctx->in = cl->next;

                *last_out = cl;
                last_out = &cl->next;
                cl->next = NULL;

                continue;
            }

			//	ctx->buf如果为空，将申请一个buf使用，下边的合并函数将要使用此buf
            if (ctx->buf == NULL) {

				//	为文件申请一个buf, ctx->buf指向的是新申请的
                rc = ngx_output_chain_align_file_buf(ctx, bsize);

                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

                if (rc != NGX_OK) {

                    if (ctx->free) {

                        /* get the free buf */

                        cl = ctx->free;
                        ctx->buf = cl->buf;
                        ctx->free = cl->next;

                        ngx_free_chain(ctx->pool, cl);

                    } else if (out || ctx->allocated == ctx->bufs.num) {

                        break;

                    } else if (ngx_output_chain_get_buf(ctx, bsize) != NGX_OK) {
                        return NGX_ERROR;
                    }
                }
            }

			//	拷贝 ctx->in 的数据到 ctx->buf
            rc = ngx_output_chain_copy_buf(ctx);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (rc == NGX_AGAIN) {
                if (out) {
                    break;
                }

                return rc;
            }

            /* delete the completed buf from the ctx->in chain */

			/*	此处获取缓冲数据大小时由于在 ngx_output_chain_copy_buf（）函数中已经将解析完的偏移指针指向了解析后的地址，所以这里等于0；
				并将ctx->in指针指向下一个节点，也就是说此处仅拷贝了chain链中的第一个chain */
            if (ngx_buf_size(ctx->in->buf) == 0) {			
                ctx->in = ctx->in->next;
            }

			//	拼装输出chain链（变量 *out 指向此链的head）
            cl = ngx_alloc_chain_link(ctx->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            cl->buf = ctx->buf;
            cl->next = NULL;
            *last_out = cl;						//	将cl 指向 out
            last_out = &cl->next;
            ctx->buf = NULL;

        }	//	while end

        if (out == NULL && last != NGX_NONE) {

            if (ctx->in) {
                return NGX_AGAIN;
            }

            return last;
        }

		//	调用后续filter链
        last = ctx->output_filter(ctx->filter_ctx, out);				//	ngx_http_next_filter 或 ngx_chain_writer

        if (last == NGX_ERROR || last == NGX_DONE) {
            return last;
        }

		//	更新已发送完的chain到free, 为发送完的到Busy
        ngx_chain_update_chains(ctx->pool, &ctx->free, &ctx->busy, &out,
                                ctx->tag);
        last_out = &out;
    }	//	end for
}

/*
 *	函数主要用来判断是否需要复制buf。返回1,表示不需要拷贝，否则为需要拷贝 
 */
static ngx_inline ngx_int_t
ngx_output_chain_as_is(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf)
{
    ngx_uint_t  sendfile;

	//	是否为specialbuf，是的话返回1,也就是不用拷贝 
    if (ngx_buf_special(buf)) {
        return 1;
    }

	//	如果buf在文件中，并且使用了directio的话，需要拷贝buf  
    if (buf->in_file && buf->file->directio) {
        return 0;
    }

    sendfile = ctx->sendfile;

#if (NGX_SENDFILE_LIMIT)

    if (buf->in_file && buf->file_pos >= NGX_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif

    if (!sendfile) {		//	不使用sendfile时

        if (!ngx_buf_in_memory(buf)) {
            return 0;
        }

        buf->in_file = 0;
    }

	//	???????????
    if (ctx->need_in_memory && !ngx_buf_in_memory(buf)) {
        return 0;
    }

	//	????????????
    if (ctx->need_in_temp && (buf->memory || buf->mmap)) {
        return 0;
    }

    return 1;
}

/*
 *	合并chain
 *	将参数3中的chain加入到参数2的chain链表中
 */
static ngx_int_t
ngx_output_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;
#if (NGX_SENDFILE_LIMIT)
    ngx_buf_t    *b, *buf;
#endif

    ll = chain;

	//	找到chain链表的最后一个（chain = &ctx->in）
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {

		//	获取一个chain
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

#if (NGX_SENDFILE_LIMIT)

        buf = in->buf;

        if (buf->in_file
            && buf->file_pos < NGX_SENDFILE_LIMIT
            && buf->file_last > NGX_SENDFILE_LIMIT)
        {
            /* split a file buf on two bufs by the sendfile limit */

            b = ngx_calloc_buf(pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, buf, sizeof(ngx_buf_t));

            if (ngx_buf_in_memory(buf)) {
                buf->pos += (ssize_t) (NGX_SENDFILE_LIMIT - buf->file_pos);
                b->last = buf->pos;
            }

            buf->file_pos = NGX_SENDFILE_LIMIT;
            b->file_last = NGX_SENDFILE_LIMIT;

            cl->buf = b;

        } else {
            cl->buf = buf;				//	
            in = in->next;
        }

#else
        cl->buf = in->buf;
        in = in->next;				//	将in指向参数in的next元素，目的用于判断是否参数in是否还有数据

#endif

        cl->next = NULL;
        *ll = cl;					//	将刚申请的chain挂载到参数 chain 的末尾
        ll = &cl->next;				//	将ll指向刚申请的cl的下一个元素（因为上步已经将cl挂载到了&ctx->in的尾部，所以当再次循环时ll必须指向了&ctx->in的尾部）
    }

    return NGX_OK;
}


static ngx_int_t
ngx_output_chain_align_file_buf(ngx_output_chain_ctx_t *ctx, off_t bsize)
{
    size_t      size;
    ngx_buf_t  *in;

    in = ctx->in->buf;

	//	未开启direct io
    if (in->file == NULL || !in->file->directio) {
        return NGX_DECLINED;
    }

	//	使用directio
    ctx->directio = 1;

    size = (size_t) (in->file_pos - (in->file_pos & ~(ctx->alignment - 1)));				//	?????

    if (size == 0) {

        if (bsize >= (off_t) ctx->bufs.size) {
            return NGX_DECLINED;
        }

        size = (size_t) bsize;

    } else {
        size = (size_t) ctx->alignment - size;

        if ((off_t) size > bsize) {
            size = (size_t) bsize;
        }
    }

	//	申请一个buf，大小等于size
    ctx->buf = ngx_create_temp_buf(ctx->pool, size);
    if (ctx->buf == NULL) {
        return NGX_ERROR;
    }

    /*
     * we do not set ctx->buf->tag, because we do not want
     * to reuse the buf via ctx->free list
     */

#if (NGX_HAVE_ALIGNED_DIRECTIO)
    ctx->unaligned = 1;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_output_chain_get_buf(ngx_output_chain_ctx_t *ctx, off_t bsize)
{
    size_t       size;
    ngx_buf_t   *b, *in;
    ngx_uint_t   recycled;

    in = ctx->in->buf;
    size = ctx->bufs.size;
    recycled = 1;

    if (in->last_in_chain) {

        if (bsize < (off_t) size) {

            /*
             * allocate a small temp buf for a small last buf
             * or its small last part
             */

            size = (size_t) bsize;
            recycled = 0;

        } else if (!ctx->directio
                   && ctx->bufs.num == 1
                   && (bsize < (off_t) (size + size / 4)))
        {
            /*
             * allocate a temp buf that equals to a last buf,
             * if there is no directio, the last buf size is lesser
             * than 1.25 of bufs.size and the temp buf is single
             */

            size = (size_t) bsize;
            recycled = 0;
        }
    }

    b = ngx_calloc_buf(ctx->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (ctx->directio) {

        /*
         * allocate block aligned to a disk sector size to enable
         * userland buffer direct usage conjunctly with directio
         */

        b->start = ngx_pmemalign(ctx->pool, size, (size_t) ctx->alignment);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

    } else {
        b->start = ngx_palloc(ctx->pool, size);
        if (b->start == NULL) {
            return NGX_ERROR;
        }
    }

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;
    b->tag = ctx->tag;
    b->recycled = recycled;

    ctx->buf = b;
    ctx->allocated++;

    return NGX_OK;
}


static ngx_int_t
ngx_output_chain_copy_buf(ngx_output_chain_ctx_t *ctx)
{
    off_t        size;
    ssize_t      n;
    ngx_buf_t   *src, *dst;
    ngx_uint_t   sendfile;

    src = ctx->in->buf;
    dst = ctx->buf;

    size = ngx_buf_size(src);
    size = ngx_min(size, dst->end - dst->pos);

    sendfile = ctx->sendfile & !ctx->directio;				//	是否使用sendfile检查

#if (NGX_SENDFILE_LIMIT)

    if (src->in_file && src->file_pos >= NGX_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif

	//	需要拷贝的buf在内存中
    if (ngx_buf_in_memory(src)) {

		//	拷贝 ctx->in->buf 中的数据到 ctx->buf
        ngx_memcpy(dst->pos, src->pos, (size_t) size);
        src->pos += (size_t) size;
        dst->last += (size_t) size;

        if (src->in_file) {		//	数据在文件中

            if (sendfile) {
                dst->in_file = 1;
                dst->file = src->file;
                dst->file_pos = src->file_pos;
                dst->file_last = src->file_pos + size;

            } else {
                dst->in_file = 0;	//	不使用sendfile时
            }

            src->file_pos += size;

        } else {
            dst->in_file = 0;
        }


		//	ctx->in->buf 中的数据解析完后
        if (src->pos == src->last) {
            dst->flush = src->flush;
            dst->last_buf = src->last_buf;
            dst->last_in_chain = src->last_in_chain;
        }

    } else {

#if (NGX_HAVE_ALIGNED_DIRECTIO)

        if (ctx->unaligned) {
            if (ngx_directio_off(src->file->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, ngx_errno,
                              ngx_directio_off_n " \"%s\" failed",
                              src->file->name.data);
            }
        }

#endif

#if (NGX_HAVE_FILE_AIO)

        if (ctx->aio_handler) {
            n = ngx_file_aio_read(src->file, dst->pos, (size_t) size,
                                  src->file_pos, ctx->pool);
            if (n == NGX_AGAIN) {
                ctx->aio_handler(ctx, src->file);
                return NGX_AGAIN;
            }

        } else {
            n = ngx_read_file(src->file, dst->pos, (size_t) size,
                              src->file_pos);
        }
#else

        n = ngx_read_file(src->file, dst->pos, (size_t) size, src->file_pos);

#endif

#if (NGX_HAVE_ALIGNED_DIRECTIO)

        if (ctx->unaligned) {
            ngx_err_t  err;

            err = ngx_errno;

            if (ngx_directio_on(src->file->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, ngx_errno,
                              ngx_directio_on_n " \"%s\" failed",
                              src->file->name.data);
            }

            ngx_set_errno(err);

            ctx->unaligned = 0;
        }

#endif

        if (n == NGX_ERROR) {
            return (ngx_int_t) n;
        }

        if (n != size) {
            ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                          ngx_read_file_n " read only %z of %O from \"%s\"",
                          n, size, src->file->name.data);
            return NGX_ERROR;
        }

        dst->last += n;

        if (sendfile) {
            dst->in_file = 1;
            dst->file = src->file;
            dst->file_pos = src->file_pos;
            dst->file_last = src->file_pos + n;

        } else {
            dst->in_file = 0;
        }

        src->file_pos += n;

        if (src->file_pos == src->file_last) {
            dst->flush = src->flush;
            dst->last_buf = src->last_buf;
            dst->last_in_chain = src->last_in_chain;
        }
    }

    return NGX_OK;
}

//	貌似就upstream模块使用到了
ngx_int_t
ngx_chain_writer(void *data, ngx_chain_t *in)
{
    ngx_chain_writer_ctx_t *ctx = data;					//	获取upstream使用的writer上下文， 在ngx_http_upstream_init_request()函数中设置

    off_t              size;
    ngx_chain_t       *cl;
    ngx_connection_t  *c;

    c = ctx->connection;								//	获取与后端服务器的connection


	//	遍历发送的chain链， 将新申请的chain串起来，挂接到 ctx->out的尾部
    for (size = 0; in; in = in->next) {

#if 1
        if (ngx_buf_size(in->buf) == 0 && !ngx_buf_special(in->buf)) {
            ngx_debug_point();
        }
#endif

        size += ngx_buf_size(in->buf);

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "chain writer buf fl:%d s:%uO",
                       in->buf->flush, ngx_buf_size(in->buf));

		//	获取一个chain结构(为什么重新获取chain结构？？？？)
        cl = ngx_alloc_chain_link(ctx->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = in->buf;
        cl->next = NULL;
        *ctx->last = cl;					//	将新申请的chain串起来， 直接会挂接到 ctx->out的尾部
        ctx->last = &cl->next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "chain writer in: %p", ctx->out);

    for (cl = ctx->out; cl; cl = cl->next) {

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_debug_point();
        }

#endif

        size += ngx_buf_size(cl->buf);
    }

    if (size == 0 && !c->buffered) {			//	????
        return NGX_OK;
    }

	//	发送数据
    ctx->out = c->send_chain(c, ctx->out, ctx->limit);				//	ngx_linux_sendfile_chain()

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "chain writer out: %p", ctx->out);

    if (ctx->out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    if (ctx->out == NULL) {
        ctx->last = &ctx->out;

        if (!c->buffered) {
            return NGX_OK;
        }
    }


	//	这里表明还有数据未发送成功
    return NGX_AGAIN;
}
