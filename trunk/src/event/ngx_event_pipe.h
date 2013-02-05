
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_PIPE_H_INCLUDED_
#define _NGX_EVENT_PIPE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_event_pipe_s  ngx_event_pipe_t;

typedef ngx_int_t (*ngx_event_pipe_input_filter_pt)(ngx_event_pipe_t *p,
                                                    ngx_buf_t *buf);
typedef ngx_int_t (*ngx_event_pipe_output_filter_pt)(void *data,
                                                     ngx_chain_t *chain);


struct ngx_event_pipe_s {
    ngx_connection_t  *upstream;				//	后端服务器
    ngx_connection_t  *downstream;				//	客户端

    ngx_chain_t       *free_raw_bufs;
    ngx_chain_t       *in;
    ngx_chain_t      **last_in;

    ngx_chain_t       *out;
    ngx_chain_t       *free;					//	ngx_event_pipe_write_to_downstream()向客户端发送完数据时，会将已发送完的chain挂载到free上。
    ngx_chain_t       *busy;

    /*
     * the input filter i.e. that moves HTTP/1.1 chunks
     * from the raw bufs to an incoming chain
     */

    ngx_event_pipe_input_filter_pt    input_filter;
    void                             *input_ctx;

    ngx_event_pipe_output_filter_pt   output_filter;
    void                             *output_ctx;

    unsigned           read:1;							//	是否已经从后端服务器读取到数据
    unsigned           cacheable:1;						//	proxy_cache与proxy_store开启其中一个 p->cacheable就等于1
    unsigned           single_buf:1;
    unsigned           free_bufs:1;
    unsigned           upstream_done:1;					//	说明后端服务器的body数据部分已经全部接收完毕
    unsigned           upstream_error:1;				//	从后端服务器读取数据失败或超时
    unsigned           upstream_eof:1;					//	已从后端服务器读取完毕数据
    unsigned           upstream_blocked:1;				//	???
    unsigned           downstream_done:1;
    unsigned           downstream_error:1;				//	向客户端发送数据出错
    unsigned           cyclic_temp_file:1;				//	是否循环写临时文件

    ngx_int_t          allocated;						//	已分配的缓冲区个数，与字段 bufs 相关
    ngx_bufs_t         bufs;							//	缓冲区个数和大小（ u->conf->bufs ）
    ngx_buf_tag_t      tag;								//	模块标记

    ssize_t            busy_size;						//	u->conf->busy_buffers_size；与 指令"proxy_busy_buffers_size"、指令"proxy_buffers"、指令"proxy_buffer_size" 有关

    off_t              read_length;						//	已从后端服务器读取的数据大小累计
    off_t              length;							//	剩余未从后端服务器接收的数据大小。注：大多数情况是后端服务器反馈数据的body大小，如果后端反馈的编码时chunked，则为-1；在函数 ngx_http_proxy_input_filter_init()中被修改

    off_t              max_temp_file_size;				//	临时文件大小的上限（u->conf->max_temp_file_size）
    ssize_t            temp_file_write_size;

    ngx_msec_t         read_timeout;
    ngx_msec_t         send_timeout;
    ssize_t            send_lowat;

    ngx_pool_t        *pool;							//	使用的内存池
    ngx_log_t         *log;								//	使用的日志

    ngx_chain_t       *preread_bufs;
    size_t             preread_size;
    ngx_buf_t         *buf_to_file;

    ngx_temp_file_t   *temp_file;						//	函数ngx_http_upstream_send_response ()中申请

    /* STUB */ int     num;
};


ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write);
ngx_int_t ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
ngx_int_t ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b);


#endif /* _NGX_EVENT_PIPE_H_INCLUDED_ */
