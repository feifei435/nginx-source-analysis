
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 * On Linux up to 2.4.21 sendfile() (syscall #187) works with 32-bit
 * offsets only, and the including <sys/sendfile.h> breaks the compiling,
 * if off_t is 64 bit wide.  So we use own sendfile() definition, where offset
 * parameter is int32_t, and use sendfile() for the file parts below 2G only,
 * see src/os/unix/ngx_linux_config.h
 *
 * Linux 2.4.21 has the new sendfile64() syscall #239.
 *
 * On Linux up to 2.6.16 sendfile() does not allow to pass the count parameter
 * more than 2G-1 bytes even on 64-bit platforms: it returns EINVAL,
 * so we limit it to 2G-1 bytes.
 */

#define NGX_SENDFILE_LIMIT  2147483647L					//	约等于2G


#if (IOV_MAX > 64)
#define NGX_HEADERS  64
#else
#define NGX_HEADERS  IOV_MAX
#endif


/*
 *	sent:	在本轮发送中已经成功发送的数据大小
 *	send:	本轮发送中要发送的数据大小
 *	prev_send: 本轮发送中上次发送的数据大小
 */

ngx_chain_t *
ngx_linux_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int            rc, tcp_nodelay;
    off_t          size, send, prev_send, aligned, sent, fprev;
    u_char        *prev;
    size_t         file_size;
    ngx_err_t      err;
    ngx_buf_t     *file;
    ngx_uint_t     eintr, complete;
    ngx_array_t    header;
    ngx_event_t   *wev;
    ngx_chain_t   *cl;
    struct iovec  *iov, headers[NGX_HEADERS];
#if (NGX_HAVE_SENDFILE64)
    off_t          offset;
#else
    int32_t        offset;
#endif

    wev = c->write;				//	写事件

    if (!wev->ready) {			//	写事件未准备好，直接返回
        return in;
    }


    /* the maximum limit size is 2G-1 - the page size */

    if (limit == 0 || limit > (off_t) (NGX_SENDFILE_LIMIT - ngx_pagesize)) {
        limit = NGX_SENDFILE_LIMIT - ngx_pagesize;
    }


    send = 0;			

	//	拼装io向量数组
    header.elts = headers;
    header.size = sizeof(struct iovec);
    header.nalloc = NGX_HEADERS;
    header.pool = c->pool;

    for ( ;; ) {
        file = NULL;
        file_size = 0;
        eintr = 0;
        complete = 0;
        prev_send = send;

        header.nelts = 0;

        prev = NULL;
        iov = NULL;

        /* create the iovec and coalesce the neighbouring bufs */

		//	遍历要发送的chain链
        for (cl = in;
             cl && header.nelts < IOV_MAX && send < limit;
             cl = cl->next)
        {

			//	??????
            if (ngx_buf_special(cl->buf)) {
                continue;
            }

#if 1
            if (!ngx_buf_in_memory(cl->buf) && !cl->buf->in_file) {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              "zero size buf in sendfile "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              cl->buf->temporary,
                              cl->buf->recycled,
                              cl->buf->in_file,
                              cl->buf->start,
                              cl->buf->pos,
                              cl->buf->last,
                              cl->buf->file,
                              cl->buf->file_pos,
                              cl->buf->file_last);

                ngx_debug_point();

                return NGX_CHAIN_ERROR;
            }
#endif

            if (!ngx_buf_in_memory_only(cl->buf)) {			//	数据不在内存中
                break;
            }

            size = cl->buf->last - cl->buf->pos;			//	获取未发送的数据大小

            if (send + size > limit) {						//	当要发送数据的总和大于limit限制，仅允许发送剩余大小
                size = limit - send;
            }

            if (prev == cl->buf->pos) {				
                iov->iov_len += (size_t) size;			//	????

            } else {
                iov = ngx_array_push(&header);
                if (iov == NULL) {
                    return NGX_CHAIN_ERROR;
                }

                iov->iov_base = (void *) cl->buf->pos;
                iov->iov_len = (size_t) size;
            }

            prev = cl->buf->pos + (size_t) size;
            send += size;									//	计算要发送的数据大小
        }

        /* set TCP_CORK if there is a header before a file */

        if (c->tcp_nopush == NGX_TCP_NOPUSH_UNSET
            && header.nelts != 0
            && cl
            && cl->buf->in_file)
        {
            /* the TCP_CORK and TCP_NODELAY are mutually exclusive */

            if (c->tcp_nodelay == NGX_TCP_NODELAY_SET) {

                tcp_nodelay = 0;

                if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                               (const void *) &tcp_nodelay, sizeof(int)) == -1)
                {
                    err = ngx_errno;

                    /*
                     * there is a tiny chance to be interrupted, however,
                     * we continue a processing with the TCP_NODELAY
                     * and without the TCP_CORK
                     */

                    if (err != NGX_EINTR) {
                        wev->error = 1;
                        ngx_connection_error(c, err,
                                             "setsockopt(TCP_NODELAY) failed");
                        return NGX_CHAIN_ERROR;
                    }

                } else {
                    c->tcp_nodelay = NGX_TCP_NODELAY_UNSET;

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                                   "no tcp_nodelay");
                }
            }

            if (c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {

                if (ngx_tcp_nopush(c->fd) == NGX_ERROR) {
                    err = ngx_errno;

                    /*
                     * there is a tiny chance to be interrupted, however,
                     * we continue a processing without the TCP_CORK
                     */

                    if (err != NGX_EINTR) {
                        wev->error = 1;
                        ngx_connection_error(c, err,
                                             ngx_tcp_nopush_n " failed");
                        return NGX_CHAIN_ERROR;
                    }

                } else {
                    c->tcp_nopush = NGX_TCP_NOPUSH_SET;

                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                   "tcp_nopush");
                }
            }
        }

        /* get the file buf */

		//	如果chain链表中既有内存buf又有文件buf， 并且内存buf存在于文件Buf之前，将先发送内存buf后，在发送文件buf
        if (header.nelts == 0 
			&& cl 
			&& cl->buf->in_file				//	发送的数据在文件中
			&& send < limit
		) {
            file = cl->buf;

            /* coalesce the neighbouring file bufs */

            do {
                size = cl->buf->file_last - cl->buf->file_pos;			//	获取文件的大小

                if (send + size > limit) {
                    size = limit - send;

                    aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)			//	?????
                               & ~((off_t) ngx_pagesize - 1);

                    if (aligned <= cl->buf->file_last) {
                        size = aligned - cl->buf->file_pos;
                    }
                }

                file_size += (size_t) size;				//	统计文件的大小
                send += size;
                fprev = cl->buf->file_pos + size;
                cl = cl->next;							//	检查后续的chain链是否缓存在文件中，如果是继续拼装数据

            } while (cl
                     && cl->buf->in_file
                     && send < limit
                     && file->file->fd == cl->buf->file->fd
                     && fprev == cl->buf->file_pos);
        }


		//	在文件中使用sendfile()
        if (file) {
#if 1
            if (file_size == 0) {
                ngx_debug_point();
                return NGX_CHAIN_ERROR;
            }
#endif
#if (NGX_HAVE_SENDFILE64)
            offset = file->file_pos;
#else
            offset = (int32_t) file->file_pos;
#endif

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "sendfile: @%O %uz", file->file_pos, file_size);

            rc = sendfile(c->fd, file->file->fd, &offset, file_size);

            if (rc == -1) {
                err = ngx_errno;

                switch (err) {
                case NGX_EAGAIN:
                    break;

                case NGX_EINTR:
                    eintr = 1;
                    break;

                default:
                    wev->error = 1;
                    ngx_connection_error(c, err, "sendfile() failed");
                    return NGX_CHAIN_ERROR;
                }

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                               "sendfile() is not ready");
            }

            sent = rc > 0 ? rc : 0;

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "sendfile: %d, @%O %O:%uz",
                           rc, file->file_pos, sent, file_size);

        } else {	

			//	不在文件中使用聚集写writev()

            rc = writev(c->fd, header.elts, header.nelts);

            if (rc == -1) {
                err = ngx_errno;

                switch (err) {
                case NGX_EAGAIN:
                    break;

                case NGX_EINTR:
                    eintr = 1;
                    break;

                default:
                    wev->error = 1;
                    ngx_connection_error(c, err, "writev() failed");
                    return NGX_CHAIN_ERROR;
                }

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                               "writev() not ready");
            }

            sent = rc > 0 ? rc : 0;					//	返回写成功的字节数

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "writev: %O", sent);
        }

		//	有时不能一次将chain链中的数据一次发送出去需要多次发送，此时检查本次发送是否完成
        if (send - prev_send == sent) {
            complete = 1;
        }

        c->sent += sent;				//	计算成功发送的数据大小

		//	遍历所有chain，更新chain状态
        for (cl = in; cl; cl = cl->next) {

            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            if (sent == 0) {
                break;
            }

            size = ngx_buf_size(cl->buf);

            if (sent >= size) {				//	sent的值有可能等于n1+n2...nN的总和，如果sent大于当前size说明此chain链节点已经发送完成
                sent -= size;

                if (ngx_buf_in_memory(cl->buf)) {
                    cl->buf->pos = cl->buf->last;
                }

                if (cl->buf->in_file) {
                    cl->buf->file_pos = cl->buf->file_last;
                }

                continue;
            }

			//	chain链中有未完全发送成功，将继续发送

            if (ngx_buf_in_memory(cl->buf)) {		//	数据在内存中，更新buf的pos域
                cl->buf->pos += (size_t) sent;
            }

            if (cl->buf->in_file) {					//	数据在文件中，更新file_buf的pos域
                cl->buf->file_pos += sent;
            }

            break;
        }

        if (eintr) {				//	如果本次被信号中断，再次运行
            continue;
        }

        if (!complete) {			//	complete等于0表明系统负载过大，将直接返回未完成的chain
            wev->ready = 0;
            return cl;
        }

        if (send >= limit || cl == NULL) {		//	????
            return cl;
        }

        in = cl;		//	更新in, 准备处理下一个chain
    }	//	end for
}
