
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000100
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000200
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00000400
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00000800
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100


typedef struct {
    ngx_msec_t                       bl_time;
    ngx_uint_t                       bl_state;

    ngx_uint_t                       status;					//	后端服务器响应的状态码整数形式(ngx_http_proxy_process_status_line（）函数中赋值)
    time_t                           response_sec;
    ngx_uint_t                       response_msec;
    off_t                            response_length;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;			//	ngx_http_upstream_headers_in 静态数组的hash表（预定义后端服务器响应的指定头域的操作方式的hash表）
    ngx_array_t                      upstreams;                 //	ngx_http_upstream_srv_conf_t
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;			//	使用负载均衡的类型，默认采用 ngx_http_upstream_init_round_robin（）
    ngx_http_upstream_init_peer_pt   init;					//	使用的负载均衡类型的初始化函数
    void                            *data;					//	us->peer.data = peers; 指向的是 ngx_http_upstream_rr_peers_t（函数 ngx_http_upstream_init_round_robin()中设置）
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_addr_t                      *addrs;				//	host信息(对应的是 ngx_url_t->addrs )
    ngx_uint_t                       naddrs;			//	(对应的是 ngx_url_t->naddrs )
    ngx_uint_t                       weight;			//	server 指令指定了 weight
    ngx_uint_t                       max_fails;			//	server 指令指定了 max_fails
    time_t                           fail_timeout;		//	server 指令指定了 fail_timeout

    unsigned                         down:1;			//	server 指令指定了 down
    unsigned                         backup:1;			//	server 指令指定了 backup
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001			//	解析到"upstream"指令时使用， 调用ngx_http_upstream()函数时会设置
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020


struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;			//	在 ngx_http_upstream()函数中被设置，指向的是本层的srv_conf

    ngx_array_t                     *servers;			//	array of ngx_http_upstream_server_t

    ngx_uint_t                       flags;				//	调用函数时ngx_http_upstream_add() 指定的标记
    ngx_str_t                        host;				//	在函数 ngx_http_upstream_add() 中设置（e.g. upstream backend中的backend）
    u_char                          *file_name;			//	"/usr/local/nginx/conf/nginx.conf"
    ngx_uint_t                       line;				//	proxy在配置文件中的行号
    in_port_t                        port;				//	使用的端口号（ngx_http_upstream_add()函数中添加, 指向ngx_url_t-->port，通常在函数ngx_parse_inet_url()中解析）
    in_port_t                        default_port;		//	默认使用的端口号（ngx_http_upstream_add()函数中添加, 指向ngx_url_t-->default_port）
};


typedef struct {
    ngx_http_upstream_srv_conf_t    *upstream;

	ngx_msec_t                       connect_timeout;					/*	当调用ngx_event_connect_peer()函数与后端发起连接时，由于非阻塞连接可能连接不能立刻成功，
																		此时会返回errno = EINPROGRESS， 此时nginx需要等待连接成功的写事件触发，这个变量用于检查连接成功写事件触发的超时时间；
																		指令"proxy_connect_timeout"指定的超时时间 */
    ngx_msec_t                       send_timeout;						//	发送请求到后端服务器，可能一次并不能全部发送出去，当第二次再次可以发送的时间间隔（指令"proxy_send_timeout"）
    ngx_msec_t                       read_timeout;						//	请求成功发送到后端服务器后， 多久内需要接收到response，ngx_http_upstream_send_request()中有使用 （指令"proxy_read_timeout"）
    ngx_msec_t                       timeout;							//	?????????	

    size_t                           send_lowat;						//	指令"proxy_send_lowat" 设置
    size_t                           buffer_size;						//	指令"proxy_buffer_size" 设置

    size_t                           busy_buffers_size;
    size_t                           max_temp_file_size;
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;			//	指令 "proxy_busy_buffers_size" 设置
    size_t                           max_temp_file_size_conf;			//  指令 "proxy_max_temp_file_size" 设置 
    size_t                           temp_file_write_size_conf;			//	指令 "proxy_temp_file_write_size" 设置 

    ngx_bufs_t                       bufs;								//	指令 "proxy_buffers" 设置

    ngx_uint_t                       ignore_headers;
    ngx_uint_t                       next_upstream;
    ngx_uint_t                       store_access;						//	指令 "proxy_store_access" 指定创建文件和目录的相关权限
    ngx_flag_t                       buffering;							//	指令 "proxy_buffering" 设置
    ngx_flag_t                       pass_request_headers;				//	指令 "proxy_pass_request_headers " 设置. 初始为on
    ngx_flag_t                       pass_request_body;					//	指令 "proxy_pass_request_body" 设置

    ngx_flag_t                       ignore_client_abort;				//	指令 "proxy_ignore_client_abort" 设置
    ngx_flag_t                       intercept_errors;					//	指令 "proxy_intercept_errors" 设置
    ngx_flag_t                       cyclic_temp_file;

    ngx_path_t                      *temp_path;							//	指令 "proxy_temp_path" 设置

    ngx_hash_t                       hide_headers_hash;					/*	默认不转发到客户端的头域列表 "ngx_http_proxy_hide_headers"
																		 *	对从被代理服务器传来的不进行转发的一些特殊头做的hash表(ngx_http_proxy_merge_loc_conf()函数中创建的hash表)
																		 *	指令"proxy_pass_header"指定的头域和
																		 */

    ngx_array_t                     *hide_headers;						//	指令 "proxy_hide_header" 设置(nginx不对从被代理服务器传来的”Date”, “Server”, “X-Pad”和”X-Accel-…“应答进行转发，这个参数允许隐藏一些其他的头部字段)	
    ngx_array_t                     *pass_headers;						//	指令 "proxy_pass_header" 设置(但是如果上述提到的头部字段必须被转发，可以使用proxy_pass_header指令)

    ngx_addr_t                      *local;								//	指令 "proxy_bind" 设置

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache;

    ngx_uint_t                       cache_min_uses;					//	指令 "proxy_cache_min_uses" 设置
    ngx_uint_t                       cache_use_stale;					//	指令 "proxy_cache_use_stale" 设置
    ngx_uint_t                       cache_methods;						//	指令 "proxy_cache_methods" 设置

    ngx_flag_t                       cache_lock;						//	指令 "proxy_cache_lock" 设置
    ngx_msec_t                       cache_lock_timeout;				//	指令 "proxy_cache_lock_timeout" 设置

    ngx_array_t                     *cache_valid;						//	指令 "proxy_cache_valid" 设置
    ngx_array_t                     *cache_bypass;						//	指令 "proxy_cache_bypass" 设置
    ngx_array_t                     *no_cache;							//	指令 "proxy_no_cache" 设置
#endif

    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

    signed                           store:2;					//	指令"proxy_store"是否开启了
    unsigned                         intercept_404:1;
    unsigned                         change_buffering:1;

#if (NGX_HTTP_SSL)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;
#endif

    ngx_str_t                        module;					//	使用的模块名字("fastcgi"、"proxy"、"scgi"、"uwsgi")
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;						//	存放后端服务器响应的header

    ngx_uint_t                       status_n;						//	后端响应状态码整数形式(e.g. 200、301、302、304）( ngx_http_proxy_process_status_line() )
    ngx_str_t                        status_line;					//	后端服务器响应的状态原因字符串( ngx_http_proxy_process_status_line() )

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    off_t                            content_length_n;

    ngx_array_t                      cache_control;

    unsigned                         connection_close:1;			//	?????
    unsigned                         chunked:1;
} ngx_http_upstream_headers_in_t;			//	后端服务器响应


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    in_addr_t                       *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


struct ngx_http_upstream_s {
    ngx_http_upstream_handler_pt     read_event_handler;
    ngx_http_upstream_handler_pt     write_event_handler;

    ngx_peer_connection_t            peer;						//	此结构用于保存与后端服务器通信的变量

    ngx_event_pipe_t                *pipe;

    ngx_chain_t                     *request_bufs;				//	create_request 中进行拼装的请求chain

    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

	/*	
		将各个upstream模块的 ngx_http_upstream_conf_t 结构体赋值给此字段，
		在以下这几个模块中的loc结构体中均包含 ngx_http_upstream_conf_t 结构
		u->conf = &flcf->upstream;
		u->conf = &mlcf->upstream;
		u->conf = &plcf->upstream;
		u->conf = &scf->upstream;
		u->conf = &uwcf->upstream;
	*/
    ngx_http_upstream_conf_t        *conf;

    ngx_http_upstream_headers_in_t   headers_in;				//	存放后端服务器响应头域

    ngx_http_upstream_resolved_t    *resolved;

    ngx_buf_t                        buffer;
    off_t                            length;					//	ngx_http_upstream_process_headers()

    ngx_chain_t                     *out_bufs;
    ngx_chain_t                     *busy_bufs;
    ngx_chain_t                     *free_bufs;

    ngx_int_t                      (*input_filter_init)(void *data);
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
    void                            *input_filter_ctx;

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
    ngx_int_t                      (*create_request)(ngx_http_request_t *r);
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);
    void                           (*abort_request)(ngx_http_request_t *r);
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h);

    ngx_msec_t                       timeout;

    ngx_http_upstream_state_t       *state;							//	指向 r->upstream_states 数组中正在使用的位置， 对它的修改就是对 r->upstream_states的修改

    ngx_str_t                        method;
    ngx_str_t                        schema;
    ngx_str_t                        uri;							//	在create_request中填充

    ngx_http_cleanup_pt             *cleanup;						//	指向r->cleanup循环单链表中申请的处理upstream模块用的， ngx_http_upstream_init_request（）在函数中申请

    unsigned                         store:1;
    unsigned                         cacheable:1;
    unsigned                         accel:1;
    unsigned                         ssl:1;
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    unsigned                         buffering:1;
    unsigned                         keepalive:1;

    unsigned                         request_sent:1;				//	是否已经向后端服务器发送过请求，在 ngx_http_upstream_send_request()函数中设置
    unsigned                         header_sent:1;
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_http_upstream_param_t;


ngx_int_t ngx_http_upstream_header_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
