
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

typedef struct {
	unsigned            found:1;
	ngx_str_t           var_value;
} ngx_extend_misc_t;


struct ngx_listening_s {
    ngx_socket_t        fd;										/* [analy]   监听套接口的套接字描述符 */

    struct sockaddr    *sockaddr;								//	监听的套接口协议地址
    socklen_t           socklen;								/* size of sockaddr */
    size_t              addr_text_max_len;						//	socket地址格式为ASCII时最大的长度（在函数ngx_create_listening()中赋值）
    ngx_str_t           addr_text;								//	套接口的IP地址

    int                 type;									/* [analy]   socket的类型 -> SOCK_STREAM */

    int                 backlog;								/* [analy]   listen的backlog */
    int                 rcvbuf;									/* [analy]   监听套接口的接收缓冲区的长度 */					
    int                 sndbuf;									/* [analy]   监听套接口的发送缓冲区的长度 */
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;

    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;
    ngx_log_t          *logp;

    size_t              pool_size;							//	作为connection使用的内存池
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;					//	指令"client_header_timeout"设置；在函数ngx_http_add_listening()中被赋值，默认60s

    ngx_listening_t    *previous;
    ngx_connection_t   *connection;								//	监听也是一个连接，要分配给监听一个连接资源

    unsigned            open:1;
    unsigned            remain:1;
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;								/* [analy]   是否已成功listen，成功listen=1 */
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:2;
#endif
    unsigned            keepalive:2;

#if (NGX_HAVE_DEFERRED_ACCEPT)
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

};


typedef enum {
     NGX_ERROR_ALERT = 0,
     NGX_ERROR_ERR,
     NGX_ERROR_INFO,
     NGX_ERROR_IGNORE_ECONNRESET,
     NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
     NGX_TCP_NODELAY_UNSET = 0,
     NGX_TCP_NODELAY_SET,
     NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET,
     NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01


struct ngx_connection_s {
	void               *data;				//	指向连接池中下一个元素，最后一个元素此字段等于NULL
    ngx_event_t        *read;				//	读事件，与cycle字段中read_events数组对应
    ngx_event_t        *write;				//	写事件

    ngx_socket_t        fd;					//	用于通信的socket描述符(本地与客户端或服务器端通信的socket描述符)

    ngx_recv_pt         recv;				//	ngx_unix_recv()
    ngx_send_pt         send;				//	ngx_unix_send()
    ngx_recv_chain_pt   recv_chain;			//	ngx_readv_chain
    ngx_send_chain_pt   send_chain;			//	ngx_linux_sendfile_chain(){此版本是系统支持sendfile情况使用} | ngx_writev_chain()
	
	ngx_extend_misc_t   extendBackup;

    ngx_listening_t    *listening;			//	该连接对应的监听

    off_t               sent;				//	发送缓冲区数据的位置偏移量

    ngx_log_t          *log;				//	日志指针

    ngx_pool_t         *pool;				//	内存池指针

    struct sockaddr    *sockaddr;			//	保存客户端的地址信息(有什么用？？？？)
    socklen_t           socklen;
    ngx_str_t           addr_text;			//	保存与服务器连接的客户端socket信息（ngx_event_accept（）函数中赋值，并且保存格式为ACSII）

#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

    struct sockaddr    *local_sockaddr;		//	保存本地监听的套接口信息

    ngx_buf_t          *buffer;					//	存放客户端请求头的缓冲区，大小根据指令“client_header_buffer_size”（在函数 ngx_http_init_request() 中申请）

    ngx_queue_t         queue;					//	连接队列的结点（ngx_reusable_connection（））

    ngx_atomic_uint_t   number;

    ngx_uint_t          requests;				//	连接中所有请求之和

    unsigned            buffered:8;		//	数据被延迟发送了(在函数ngx_http_write_filter()中设置NGX_HTTP_WRITE_BUFFERED)

    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    unsigned            single_connection:1;
    unsigned            unexpected_eof:1;				//	????
    unsigned            timedout:1;						//	连接超时
    unsigned            error:1;						//	在函数 ngx_http_output_filter（）中会被设置，如果
    unsigned            destroyed:1;					//	说明此连接是否已经销毁，如果已经销毁等于1

    unsigned            idle:1;					//	说明当前连接处于空闲（在函数 中设置）
    unsigned            reusable:1;				//	连接是否为再利用的（在函数 ngx_reusable_connection（）中设置）
    unsigned            close:1;				//	ngx_drain_connections()函数中设置

    unsigned            sendfile:1;			//	此连接是否使用sendfile系统调用（ngx_http_update_location_config()函数中有设置）
    unsigned            sndlowat:1;			//	是否设置了发送缓冲区下限 （ngx_send_lowat()函数中设置的）
    unsigned            tcp_nodelay:2;		/* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;		/* ngx_connection_tcp_nopush_e */

#if (NGX_HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_HAVE_AIO_SENDFILE)
    unsigned            aio_sendfile:1;
    ngx_buf_t          *busy_sendfile;
#endif

#if (NGX_THREADS)
    ngx_atomic_t        lock;
#endif
};


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, void *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
