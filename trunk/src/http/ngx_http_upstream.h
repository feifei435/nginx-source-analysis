
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

    ngx_uint_t                       status;					//	��˷�������Ӧ��״̬��������ʽ(ngx_http_proxy_process_status_line���������и�ֵ)
    time_t                           response_sec;
    ngx_uint_t                       response_msec;
    off_t                            response_length;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;			//	ngx_http_upstream_headers_in[] ��̬�����hash��Ԥ�����˷�������Ӧ��ָ��ͷ��Ĳ�����ʽ��hash��
    ngx_array_t                      upstreams;                 //	ngx_http_upstream_srv_conf_t
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;			//	ʹ�ø��ؾ�������ͣ�Ĭ�ϲ��� ngx_http_upstream_init_round_robin����
    ngx_http_upstream_init_peer_pt   init;					//	ʹ�õĸ��ؾ������͵ĳ�ʼ������
    void                            *data;					//	ָ���ؾ���ʹ�õĹ���ṹ	��us->peer.data = peers; ָ����� ngx_http_upstream_rr_peers_t������ ngx_http_upstream_init_round_robin()�����ã�
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_addr_t                      *addrs;				//	host��Ϣ(��Ӧ���� ngx_url_t->addrs )
    ngx_uint_t                       naddrs;			//	(��Ӧ���� ngx_url_t->naddrs )
    ngx_uint_t                       weight;			//	server ָ��ָ���� weight
    ngx_uint_t                       max_fails;			//	server ָ��ָ���� max_fails
    time_t                           fail_timeout;		//	server ָ��ָ���� fail_timeout

    unsigned                         down:1;			//	��ʶ�˷�������������״̬��server ָ��ָ���� down��
    unsigned                         backup:1;			//	��ʶ�˷�����Ϊ���ݷ�������server ָ��ָ���� backup��
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001			//	������"upstream"ָ��ʱʹ�ã� ����ngx_http_upstream()����ʱ������
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020


struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;			//	�� ngx_http_upstream()�����б����ã�ָ����Ǳ����srv_conf

    ngx_array_t                     *servers;			//	array of ngx_http_upstream_server_t

    ngx_uint_t                       flags;				//	���ú���ʱngx_http_upstream_add() ָ���ı��
    ngx_str_t                        host;				//	�ں��� ngx_http_upstream_add() �����ã�e.g. upstream backend�е�backend��
    u_char                          *file_name;			//	"/usr/local/nginx/conf/nginx.conf"
    ngx_uint_t                       line;				//	proxy�������ļ��е��к�
    in_port_t                        port;				//	ʹ�õĶ˿ںţ�ngx_http_upstream_add()���������, ָ��ngx_url_t-->port��ͨ���ں���ngx_parse_inet_url()�н�����
    in_port_t                        default_port;		//	Ĭ��ʹ�õĶ˿ںţ�ngx_http_upstream_add()���������, ָ��ngx_url_t-->default_port��
};


typedef struct {
    ngx_http_upstream_srv_conf_t    *upstream;

	ngx_msec_t                       connect_timeout;					/*	������ngx_event_connect_peer()�������˷�������ʱ�����ڷ��������ӿ������Ӳ������̳ɹ���
																		��ʱ�᷵��errno = EINPROGRESS�� ��ʱnginx��Ҫ�ȴ����ӳɹ���д�¼�����������������ڼ�����ӳɹ�д�¼������ĳ�ʱʱ�䣻
																		ָ��"proxy_connect_timeout"ָ���ĳ�ʱʱ�� */
    ngx_msec_t                       send_timeout;						//	�������󵽺�˷�����������һ�β�����ȫ�����ͳ�ȥ�����ڶ����ٴο��Է��͵�ʱ������ָ��"proxy_send_timeout"��
    ngx_msec_t                       read_timeout;						//	����ɹ����͵���˷������� �������Ҫ���յ�response��ngx_http_upstream_send_request()����ʹ�� ��ָ��"proxy_read_timeout"��
    ngx_msec_t                       timeout;							//	?????????	

    size_t                           send_lowat;						//	ָ��"proxy_send_lowat" ����
    size_t                           buffer_size;						//	���պ�˷����������Ļ�������С��ָ��"proxy_buffer_size" ����

    size_t                           busy_buffers_size;					/*	���ָ�� "proxy_busy_buffers_size" δָ��������ֵ��ָ�� "proxy_buffer_size" �� "proxy_buffers" �����ֵ��������
																			��������ֵ����ָ�� "proxy_busy_buffers_size" ��ֵ */

    size_t                           max_temp_file_size;				/*	����ֶΡ�max_temp_file_size_conf�������ã����ֶν����ݡ�max_temp_file_size_conf��ȡֵ 
																			δ����ʱ����ʹ��Ĭ��ֵ1024 * 1024 * 1024; */

    size_t                           temp_file_write_size;				//	???

    size_t                           busy_buffers_size_conf;			//	ָ�� "proxy_busy_buffers_size" ����
    size_t                           max_temp_file_size_conf;			//  ��ʱ�ļ���С�����ޣ�buffering��˷���������������ʱ����˷��������������ݲ�����ȫ���뻺����ʱ����д����ʱ�ļ���ָ�� "proxy_max_temp_file_size" ���� 
    size_t                           temp_file_write_size_conf;			//	ָ�� "proxy_temp_file_write_size" ���� 

    ngx_bufs_t                       bufs;								//	ָ�� "proxy_buffers" ���ã�Ĭ����8����С4K��8K���ں���ngx_http_upstream_send_response()�����ã�

    ngx_uint_t                       ignore_headers;
    ngx_uint_t                       next_upstream;						//	ȷ�Ϻ�������½�����ת������һ���������� ָ�� "proxy_next_upstream"�� ngx_http_proxy_next_upstream_masks
    ngx_uint_t                       store_access;						//	ָ�� "proxy_store_access" ָ�������ļ���Ŀ¼�����Ȩ��
    ngx_flag_t                       buffering;							//	ָ�� "proxy_buffering" ���ã� Ĭ��ֵon
    ngx_flag_t                       pass_request_headers;				//	ָ�� "proxy_pass_request_headers " ����. ��ʼΪon
    ngx_flag_t                       pass_request_body;					//	ָ�� "proxy_pass_request_body" ����

    ngx_flag_t                       ignore_client_abort;				//	ָ�� "proxy_ignore_client_abort" ����
    ngx_flag_t                       intercept_errors;					//	ָ�� "proxy_intercept_errors" ����
    ngx_flag_t                       cyclic_temp_file;

    ngx_path_t                      *temp_path;							//	ָ�� "proxy_temp_path" ����

    ngx_hash_t                       hide_headers_hash;					/*	Ĭ�ϲ�ת�����ͻ��˵�ͷ���б� "ngx_http_proxy_hide_headers"
																		 *	�Դӱ���������������Ĳ�����ת����һЩ����ͷ����hash��(ngx_http_proxy_merge_loc_conf()�����д�����hash��)
																		 *	ָ��"proxy_pass_header"ָ����ͷ���
																		 */

    ngx_array_t                     *hide_headers;						//	ָ�� "proxy_hide_header" ����(nginx���Դӱ���������������ġ�Date��, ��Server��, ��X-Pad���͡�X-Accel-����Ӧ�����ת�������������������һЩ������ͷ���ֶ�)	
    ngx_array_t                     *pass_headers;						//	ָ�� "proxy_pass_header" ����(������������ᵽ��ͷ���ֶα��뱻ת��������ʹ��proxy_pass_headerָ��)

    ngx_addr_t                      *local;								//	���˷�������ǰ���󶨱���IP�Ͷ˿���Ϣ��ָ�� "proxy_bind" ���ã�ngx_http_upstream_init_request()����������

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache;								//	ָ�� "proxy_cache", Ĭ��off=NULL(����ngx_http_proxy_cache����������)

    ngx_uint_t                       cache_min_uses;					//	ָ�� "proxy_cache_min_uses" ����
    ngx_uint_t                       cache_use_stale;					//	ָ�� "proxy_cache_use_stale" ����
    ngx_uint_t                       cache_methods;						//	ָ�� "proxy_cache_methods" ����

    ngx_flag_t                       cache_lock;						//	ָ�� "proxy_cache_lock" ����
    ngx_msec_t                       cache_lock_timeout;				//	ָ�� "proxy_cache_lock_timeout" ����

    ngx_array_t                     *cache_valid;						//	ָ�� "proxy_cache_valid" ����
    ngx_array_t                     *cache_bypass;						//	ָ�� "proxy_cache_bypass" ����
    ngx_array_t                     *no_cache;							//	ָ�� "proxy_no_cache" ����
#endif

    ngx_array_t                     *store_lengths;						//	ָ�� "proxy_store" ������ʹ���˱���
    ngx_array_t                     *store_values;

    signed                           store:2;							//	off=0��on=1��			ָ��"proxy_store"�Ƿ�����
    unsigned                         intercept_404:1;
    unsigned                         change_buffering:1;

#if (NGX_HTTP_SSL)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;
#endif

    ngx_str_t                        module;							//	ʹ�õ�ģ������("fastcgi"��"proxy"��"scgi"��"uwsgi")
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;				//	�����յ���˷���������������ͷʱ����һ���н����������õ�u->headers_in�ṹ�� (�ں��� ngx_http_proxy_process_header() ���е���)
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;			//	��u->headers_in�ṹ��ͷ�����õ�r->headers_out(�ں��� ngx_http_upstream_process_headers() �е���)
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;				/* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;						//	��ź�˷�������Ӧ��header

    ngx_uint_t                       status_n;						//	�����Ӧ״̬��������ʽ(e.g. 200��301��302��304��( ngx_http_proxy_process_status_line() )
    ngx_str_t                        status_line;					//	��˷�������Ӧ��״̬ԭ���ַ���( ngx_http_proxy_process_status_line() )

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
    ngx_table_elt_t                 *content_length;				//	ָ���˷�������������Ӧͷ�е�"content_length"ͷ��
	
    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;				//	"Transfer-Encoding" �д�ͷ��ʱ

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    off_t                            content_length_n;				//	"content_length"ͷ���������ʽ�� ���ֶ� "*content_length" ��ﺬ����ͬ

    ngx_array_t                      cache_control;

    unsigned                         connection_close:1;			//	��˷�����������Connection: close;					ngx_http_upstream_process_connection()����������
    unsigned                         chunked:1;						//	��˷�����������Transfer-Encoding: chunked;			ngx_http_upstream_process_transfer_encoding()����������
} ngx_http_upstream_headers_in_t;			//	��˷�������Ӧ


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

    ngx_peer_connection_t            peer;						//	�˽ṹ���ڱ������˷�����ͨ�ŵı���

    ngx_event_pipe_t                *pipe;						//	(e.g. ������ngx_http_proxy_handler()������)

    ngx_chain_t                     *request_bufs;				//	create_request �н���ƴװ������chain��e.g. ngx_http_proxy_create_request()���������ã�

    ngx_output_chain_ctx_t           output;					//	upstream���˷�������ʱ������buf�Ľṹ��
    ngx_chain_writer_ctx_t           writer;

	/*	
		������upstreamģ��� ngx_http_upstream_conf_t �ṹ�帳ֵ�����ֶΣ�
		�������⼸��ģ���е�loc�ṹ���о����� ngx_http_upstream_conf_t �ṹ
		u->conf = &flcf->upstream;
		u->conf = &mlcf->upstream;
		u->conf = &plcf->upstream;
		u->conf = &scf->upstream;
		u->conf = &uwcf->upstream;
	*/
    ngx_http_upstream_conf_t        *conf;

    ngx_http_upstream_headers_in_t   headers_in;				//	��ź�˷�������Ӧͷ��

    ngx_http_upstream_resolved_t    *resolved;					//	ngx_http_proxy_eval()�����д���

    ngx_buf_t                        buffer;					//	�����˷��������� (�ں��� ngx_http_upstream_process_header()������)
    off_t                            length;					//	��˷�����������"u->headers_in.content_length_n"���ȣ���chunked����ʱ����ngx_http_upstream_process_headers()�����ã�

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

    ngx_http_upstream_state_t       *state;							//	ָ�� r->upstream_states ����������ʹ�õ�λ�ã� �������޸ľ��Ƕ� r->upstream_states���޸�

    ngx_str_t                        method;
    ngx_str_t                        schema;
    ngx_str_t                        uri;							//	��create_request�����

    ngx_http_cleanup_pt             *cleanup;						//	ָ��r->cleanupѭ��������������Ĵ���upstreamģ���õģ� ngx_http_upstream_init_request�����ں���������

    unsigned                         store:1;						//	��ָ�� "proxy_store" ����ʱ����ֵΪ1���ں���ngx_http_upstream_init_request���������ã�
    unsigned                         cacheable:1;					//	???
    unsigned                         accel:1;
    unsigned                         ssl:1;
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    unsigned                         buffering:1;					//	�����˷�������������Ӧ���ݣ�ngx_http_proxy_handler()����������, ����proxyģ���ָ�� "proxy_buffering"����
    unsigned                         keepalive:1;					//	���ֶ� u->headers_in.connection_close ���

    unsigned                         request_sent:1;				//	�Ƿ��Ѿ����˷��������͹������� ngx_http_upstream_send_request()����������
    unsigned                         header_sent:1;					//	��˷���������Ӧͷ�Ƿ��Ѿ����͸��ͻ��� (ngx_http_upstream_send_response()����������)
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
