
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_MAX_URI_CHANGES           10						//	���URI���ض������
#define NGX_HTTP_MAX_SUBREQUESTS           200						//	������������

/* must be 2^n */
#define NGX_HTTP_LC_HEADER_LEN             32


#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096						//	request_discard_buffer_size
#define NGX_HTTP_LINGERING_BUFFER_SIZE     4096


#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001

#define NGX_HTTP_UNKNOWN                   0x0001
#define NGX_HTTP_GET                       0x0002
#define NGX_HTTP_HEAD                      0x0004
#define NGX_HTTP_POST                      0x0008
#define NGX_HTTP_PUT                       0x0010
#define NGX_HTTP_DELETE                    0x0020
#define NGX_HTTP_MKCOL                     0x0040
#define NGX_HTTP_COPY                      0x0080
#define NGX_HTTP_MOVE                      0x0100
#define NGX_HTTP_OPTIONS                   0x0200
#define NGX_HTTP_PROPFIND                  0x0400
#define NGX_HTTP_PROPPATCH                 0x0800
#define NGX_HTTP_LOCK                      0x1000
#define NGX_HTTP_UNLOCK                    0x2000
#define NGX_HTTP_PATCH                     0x4000
#define NGX_HTTP_TRACE                     0x8000

#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2


#define NGX_NONE                           1


#define NGX_HTTP_PARSE_HEADER_DONE         1

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_INVALID_09_METHOD   12

#define NGX_HTTP_PARSE_INVALID_HEADER      13


/* unused                                  1 */
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2					//	???
#define NGX_HTTP_SUBREQUEST_WAITED         4
#define NGX_HTTP_LOG_UNSAFE                8


#define NGX_HTTP_OK                        200
#define NGX_HTTP_CREATED                   201
#define NGX_HTTP_ACCEPTED                  202
#define NGX_HTTP_NO_CONTENT                204
#define NGX_HTTP_PARTIAL_CONTENT           206

#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_SEE_OTHER                 303
#define NGX_HTTP_NOT_MODIFIED              304
#define NGX_HTTP_TEMPORARY_REDIRECT        307

#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_UNAUTHORIZED              401
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_CONFLICT                  409
#define NGX_HTTP_LENGTH_REQUIRED           411
#define NGX_HTTP_PRECONDITION_FAILED       412
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define NGX_HTTP_CLOSE                     444

#define NGX_HTTP_NGINX_CODES               494

#define NGX_HTTP_REQUEST_HEADER_TOO_LARGE  494

#define NGX_HTTPS_CERT_ERROR               495
#define NGX_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define NGX_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499


#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#define NGX_HTTP_INSUFFICIENT_STORAGE      507


#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0			//	δʹ�õ�
#define NGX_HTTP_WRITE_BUFFERED            0x10			//	�����ʾ�����յ�write filter�б�buffered
#define NGX_HTTP_GZIP_BUFFERED             0x20
#define NGX_HTTP_SSI_BUFFERED              0x01
#define NGX_HTTP_SUB_BUFFERED              0x02
#define NGX_HTTP_COPY_BUFFERED             0x04


typedef enum {
    NGX_HTTP_INITING_REQUEST_STATE = 0,
    NGX_HTTP_READING_REQUEST_STATE,
    NGX_HTTP_PROCESS_REQUEST_STATE,

    NGX_HTTP_CONNECT_UPSTREAM_STATE,
    NGX_HTTP_WRITING_UPSTREAM_STATE,
    NGX_HTTP_READING_UPSTREAM_STATE,

    NGX_HTTP_WRITING_REQUEST_STATE,
    NGX_HTTP_LINGERING_CLOSE_STATE,
    NGX_HTTP_KEEPALIVE_STATE
} ngx_http_state_e;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
    ngx_http_header_handler_pt        handler;
} ngx_http_header_t;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
} ngx_http_header_out_t;


typedef struct {
    ngx_list_t                        headers;						//	���client����ͷ�е�����header name, �ں��� ngx_http_process_request_headers����������

    ngx_table_elt_t                  *host;							//	�������ͷ����host�ֶΣ�������ӵ�headers�б��Ȼ��ʹhostָ��ָ�������е�λ��
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *if_unmodified_since;			//	����ͷ�а���if_unmodified_since�ܶ�(���ض�ʱ���ڣ�δ���κ��޸�ʱ)
    ngx_table_elt_t                  *user_agent;
    ngx_table_elt_t                  *referer;
    ngx_table_elt_t                  *content_length;				//	ָ�� "content_length" ����ͷ��ָ��������body�ĳ���
    ngx_table_elt_t                  *content_type;

    ngx_table_elt_t                  *range;
    ngx_table_elt_t                  *if_range;

    ngx_table_elt_t                  *transfer_encoding;
    ngx_table_elt_t                  *expect;						//	request header field "Expect: 100-continue"

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                  *accept_encoding;				//	�����ֶ� accept_encoding
    ngx_table_elt_t                  *via;
#endif

    ngx_table_elt_t                  *authorization;

    ngx_table_elt_t                  *keep_alive;					//	client���͵�request����ͷ�а�����"Keep-alive:"��

#if (NGX_HTTP_PROXY || NGX_HTTP_REALIP || NGX_HTTP_GEO)
    ngx_table_elt_t                  *x_forwarded_for;
#endif

#if (NGX_HTTP_REALIP)
    ngx_table_elt_t                  *x_real_ip;					//	������ͷ�а������ֶ�ʱ����Ϊ��
#endif

#if (NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept;
    ngx_table_elt_t                  *accept_language;
#endif

#if (NGX_HTTP_DAV)
    ngx_table_elt_t                  *depth;
    ngx_table_elt_t                  *destination;
    ngx_table_elt_t                  *overwrite;
    ngx_table_elt_t                  *date;
#endif

    ngx_str_t                         user;
    ngx_str_t                         passwd;

    ngx_array_t                       cookies;

    ngx_str_t                         server;						//	ָ������ͷ��host�ֶ�
    off_t                             content_length_n;				//	content_lengthָ�������ֵ
    time_t                            keep_alive_n;

    unsigned                          connection_type:2;			//	�ͻ����������ͣ�close��keepalive��http1.1 keepalive����
    unsigned                          msie:1;
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
} ngx_http_headers_in_t;

/* 
 *	[analy]	���������п������õ�HTTP Response Header��Ϣ, ���ﲢ����������HTTPͷ��Ϣ 
 */	
typedef struct {
    ngx_list_t                        headers;							//	list of ngx_table_elt_t

    ngx_uint_t                        status;							//	response status code (e.g. ״̬�룺200)
    ngx_str_t                         status_line;

    ngx_table_elt_t                  *server;
    ngx_table_elt_t                  *date;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_encoding;					//	
    ngx_table_elt_t                  *location;
    ngx_table_elt_t                  *refresh;
    ngx_table_elt_t                  *last_modified;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *accept_ranges;
    ngx_table_elt_t                  *www_authenticate;
    ngx_table_elt_t                  *expires;
    ngx_table_elt_t                  *etag;

    ngx_str_t                        *override_charset;

    size_t                            content_type_len;					
    ngx_str_t                         content_type;						//	���� content_type�� ���������������ݵ����ͺͱ������ͣ�
    ngx_str_t                         charset;
    u_char                           *content_type_lowcase;
    ngx_uint_t                        content_type_hash;

    ngx_array_t                       cache_control;

    off_t                             content_length_n;					//	����response body length
    time_t                            date_time;
    time_t                            last_modified_time;
} ngx_http_headers_out_t;				


typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);

typedef struct {
    ngx_temp_file_t                  *temp_file;
    ngx_chain_t                      *bufs;
    ngx_buf_t                        *buf;
    off_t                             rest;
    ngx_chain_t                      *to_write;
    ngx_http_client_body_handler_pt   post_handler;
} ngx_http_request_body_t;


typedef struct {
    ngx_http_request_t               *request;

    ngx_buf_t                       **busy;
    ngx_int_t                         nbusy;

    ngx_buf_t                       **free;
    ngx_int_t                         nfree;

    ngx_uint_t                        pipeline;    /* unsigned  pipeline:1; */
} ngx_http_connection_t;


typedef struct ngx_http_server_name_s  ngx_http_server_name_t;


typedef struct {
     ngx_hash_combined_t              names;

     ngx_uint_t                       nregex;
     ngx_http_server_name_t          *regex;
} ngx_http_virtual_names_t;


typedef void (*ngx_http_cleanup_pt)(void *data);

typedef struct ngx_http_cleanup_s  ngx_http_cleanup_t;

struct ngx_http_cleanup_s {
    ngx_http_cleanup_pt               handler;
    void                             *data;
    ngx_http_cleanup_t               *next;
};


typedef ngx_int_t (*ngx_http_post_subrequest_pt)(ngx_http_request_t *r,
    void *data, ngx_int_t rc);

typedef struct {
    ngx_http_post_subrequest_pt       handler;
    void                             *data;
} ngx_http_post_subrequest_t;


typedef struct ngx_http_postponed_request_s  ngx_http_postponed_request_t;

struct ngx_http_postponed_request_s {
    ngx_http_request_t               *request;
    ngx_chain_t                      *out;
    ngx_http_postponed_request_t     *next;
};


typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;

struct ngx_http_posted_request_s {
    ngx_http_request_t               *request;
    ngx_http_posted_request_t        *next;
};


typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);
typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);


struct ngx_http_request_s {
    uint32_t                          signature;         /* "HTTP" */

    ngx_connection_t                 *connection;

    void                            **ctx;										//	http�и���ģ��ʹ�õ�ctx���� ngx_http_init_request�������������룬 �ͷ���ʲôλ�ã�
    void                            **main_conf;
    void                            **srv_conf;
    void                            **loc_conf;

    ngx_http_event_handler_pt         read_event_handler;						//	���� ngx_http_request_handler���� �е��ã� ngx_http_request_handler�������¼��ɶ����д�Ǵ���
    ngx_http_event_handler_pt         write_event_handler;						//	���� ngx_http_request_handler���� �е���

#if (NGX_HTTP_CACHE)
    ngx_http_cache_t                 *cache;									//	ngx_http_file_cache_new()�����и�ֵ
#endif

    ngx_http_upstream_t              *upstream;						//	ngx_http_upstream_create()�����������
    ngx_array_t                      *upstream_states;              //	�ں���ngx_http_upstream_init_request�����д���������			/* of ngx_http_upstream_state_t */

    ngx_pool_t                       *pool;							//	request������ʹ�õ��ڴ��
    ngx_buf_t                        *header_in;					//	����recv�Ⱥ�����ȡ����header��Ϣ�Ļ��棬ͨ����������header���з���

    ngx_http_headers_in_t             headers_in;					//	�ͻ�������header�Ľṹ��
    ngx_http_headers_out_t            headers_out;					//	��Ӧ���ͻ��˵�ͷ��ṹ��

    ngx_http_request_body_t          *request_body;					//	ngx_http_read_client_request_body()����������
	
    time_t                            lingering_time;
    time_t                            start_sec;
    ngx_msec_t                        start_msec;

    ngx_uint_t                        method;						//	�������е�methodֵ��NGX_HTTP_GET��NGX_HTTP_PUT��NGX_HTTP_POST��
    ngx_uint_t                        http_version;					//	����ͷ�����ΰ汾�ŵ�ƴװ��e.g. http1.1 = 1001)

    ngx_str_t                         request_line;					//	�����е����� (e.g. "GET / HTTP/1.1")
    ngx_str_t                         uri;							//	��������uri����(e.g. "/", ��һ���ֽ�)
    ngx_str_t                         args;
    ngx_str_t                         exten;						//	uri�е��ļ���׺�ں���ngx_http_process_request_line()������ ��e.g. index.html�е�html��
    ngx_str_t                         unparsed_uri;					//	������������ԭʼ��uri����δ���������ģ�uri�и������͵ģ�

    ngx_str_t                         method_name;					//	�������е�method�ַ���ֵ��GET��PUT��POST��
    ngx_str_t                         http_protocol;				//	�������е�httpЭ��汾�ַ���(e.g. "HTTP/1.1")

	ngx_chain_t                      *out;							//	���chain���������һ�λ�û�б������buf������ÿ�����ǽ��յ��µ�chain�Ļ���
																	//	����Ҫ���µ�chain���ӵ��ϵ�out chain�ϣ�Ȼ���ٷ���ȥ�� 
    ngx_http_request_t               *main;							//	������ĸ�����( ��ngx_http_init_request()�����н�����Ϊ��ǰ��request )
    ngx_http_request_t               *parent;						//	������ĸ�����( �ں���ngx_http_subrequest()������ )
    ngx_http_postponed_request_t     *postponed;
    ngx_http_post_subrequest_t       *post_subrequest;
    ngx_http_posted_request_t        *posted_requests;

    ngx_http_virtual_names_t         *virtual_names;

    ngx_int_t                         phase_handler;				//	������phase�е�handlerʱ���ô��ֶα�ʶphase����һ��Ҫִ�е�handler���±�
    ngx_http_handler_pt               content_handler;				//	��handler�����ú�ִ���꽫�˳�phase�����д���
    ngx_uint_t                        access_code;

	/* ������ÿ�������е�ֵ�ǲ�һ���ģ�Ҳ����˵������������ص�
	 ������ngx_http_request_s ����һ���������飬��Ҫ���ڻ��浱ǰ����ı������
	 �Ӷ����Ա���һ�������Ķ�μ����������һ�εı����Ͳ����ټ�����
	 �����汣���һ��������������ֵ���Ƿ񻺴棬ҲҪ�ɱ��������������� */
    ngx_http_variable_value_t        *variables;					//	array of ngx_http_variable_value_t

#if (NGX_PCRE)
    ngx_uint_t                        ncaptures;
    int                              *captures;
    u_char                           *captures_data;
#endif

    size_t                            limit_rate;					//	�������ʣ�����ngx_http_core_loc_conf_t->limit_rateֵ���ã�ngx_http_update_location_config()���������ã�

    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;					//	��Ϣͷ���ȣ��� ngx_http_header_filter���������������ã�

    off_t                             request_length;				//	����ͷ�ĳ���

    ngx_uint_t                        err_status;					//	???

    ngx_http_connection_t            *http_connection;

    ngx_http_log_handler_pt           log_handler;

    ngx_http_cleanup_t               *cleanup;						//	ngx_http_cleanup_t���͵ĵ���ѭ���б�

    unsigned                          subrequests:8;				//	subrequests����������ngx_http_init_request()�����г�ʼ����
    unsigned                          count:8;						//	(��ֵ�ں��� ngx_http_subrequest()��ngx_http_internal_redirect������ngx_http_named_location����
    unsigned                          blocked:8;					//	???????

    unsigned                          aio:1;

    unsigned                          http_state:4;

    /* URI with "/." and on Win32 with "//" */
    unsigned                          complex_uri:1;

    /* URI with "%" */
    unsigned                          quoted_uri:1;

    /* URI with "+" */
    unsigned                          plus_in_uri:1;

    /* URI with " " */
    unsigned                          space_in_uri:1;					//	???????????

    unsigned                          invalid_header:1;					//	��ʶ��ǰ����������ͷ�Ƿ���Ч�������еģ�

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;					//	??????????
    unsigned                          valid_unparsed_uri:1;				//	????????????
    unsigned                          uri_changed:1;					//	��ǰ��uri�Ƿ��ض����Ƿ�ı�
    unsigned                          uri_changes:4;					//	uri�����ض���������������10�Σ�ngx_http_init_request()�����г�ʼ��, ������ģ�

    unsigned                          request_body_in_single_buf:1;		//	ָ�� "client_body_in_single_buffer" ��ʱ��������Ϊ1
    unsigned                          request_body_in_file_only:1;		//	ָ�� "client_body_in_file_only" ��ʱ��������Ϊ1
    unsigned                          request_body_in_persistent_file:1;//	ָ�� "client_body_in_file_only" ��ʱ��������Ϊ1
    unsigned                          request_body_in_clean_file:1;		//	ָ�� "client_body_in_file_only" == 2ʱ��������Ϊ1
    unsigned                          request_body_file_group_access:1;
    unsigned                          request_body_file_log_level:3;	//	��־����

    unsigned                          subrequest_in_memory:1;			//	subrequest���еı�ǣ�ngx_http_subrequest()���������ã�������NGX_HTTP_SUBREQUEST_IN_MEMORY���ʱΪ1��
    unsigned                          waited:1;

#if (NGX_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (NGX_HTTP_GZIP)
    unsigned                          gzip_tested:1;					//	gzip��ص�����
    unsigned                          gzip_ok:1;
    unsigned                          gzip_vary:1;
#endif

    unsigned                          proxy:1;
    unsigned                          bypass_cache:1;
    unsigned                          no_cache:1;

    /*
     * instead of using the request context data in
     * ngx_http_limit_conn_module and ngx_http_limit_req_module
     * we use the single bits in the request structure
     */
    unsigned                          limit_conn_set:1;
    unsigned                          limit_req_set:1;

#if 0
    unsigned                          cacheable:1;
#endif

    unsigned                          pipeline:1;
    unsigned                          plain_http:1;					//	����ssl��
    unsigned                          chunked:1;					//	�Ƿ�Ϊchunked����
    unsigned                          header_only:1;				//	�Ƿ������Ϣͷ�������︳ֵ��������
    unsigned                          keepalive:1;					//	�Ƿ�Ϊkeepalive����( ngx_http_handler()�����и��� r->headers_in.connection_type����ȷ��)
    unsigned                          lingering_close:1;			//	???????
    unsigned                          discard_body:1;				//	����Ѿ����� ngx_http_discard_request_body����������������Ϊ1
    unsigned                          internal:1;					//	��ʾ���������ڲ���ת ��ngx_http_internal_redirect()�� ngx_http_subrequest() ���������ã�
    unsigned                          error_page:1;
    unsigned                          ignore_content_encoding:1;
    unsigned                          filter_finalize:1;			//	���� ngx_http_filter_finalize_request���������е���
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;				//	���ã��������������ں��� ngx_http_copy_filter()��������
    unsigned                          header_sent:1;
    unsigned                          expect_tested:1;				//	??????(ngx_http_subrequest() ����������)
    unsigned                          root_tested:1;
    unsigned                          done:1;
    unsigned                          logged:1;

    unsigned                          buffered:4;					//	

    unsigned                          main_filter_need_in_memory:1;		//	???
    unsigned                          filter_need_in_memory:1;
    unsigned                          filter_need_temporary:1;			//	 ngx_http_charset_filter_module.c �ļ���������, ���ֶν�Ӱ�� ngx_output_chain_ctx_t ->need_in_temp ��ֵ
    unsigned                          allow_ranges:1;

#if (NGX_STAT_STUB)
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
#endif

    /* used to parse HTTP headers */

    ngx_uint_t                        state;							//	�ڽ���request lineʱ������clientһ��δ������ȫ������û��ȫ��������ϣ�
																		//	���ݵĽ�����ǰλ�� ngx_http_parse_request_line() �����н�������

    ngx_uint_t                        header_hash;						//	header name��hashֵ
    ngx_uint_t                        lowcase_index;					//	Ӧ����header name���ַ�����
    u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN];	//	Сд�� header name�ַ�����e.g. "user-agent"��

    u_char                           *header_name_start;				//	ָ������ͷ��header name��ʼ��e.g. "User-Agent: curl/7.20.0"��
    u_char                           *header_name_end;					//	ָ������ͷ��header name������e.g. "User-Agent"��
    u_char                           *header_start;						//	ָ������ͷ��header value����ʼλ�� ��e.g. "curl/7.20.0"��
    u_char                           *header_end;						//	ָ������ͷ��header value�Ľ���λ�� ��e.g. "curl/7.20.0"��

    /*
     * a memory that can be reused after parsing a request line
     * via ngx_http_ephemeral_t
     */

    u_char                           *uri_start;					//	uri��ʼ��ַ
    u_char                           *uri_end;						//	uri������ַ
    u_char                           *uri_ext;						//	����uri�еĴ��к�׺�Ĳ����ں���ngx_http_parse_request_line()������ (e.g. index.html��html)
    u_char                           *args_start;
    u_char                           *request_start;				//	����Ŀ�ʼ��ַ-> "GET .. ... .. "
    u_char                           *request_end;					//	�����еĽ�����ַ	
    u_char                           *method_end;					//	ethod�Ľ�����ַ-> "GET URL VER", �ַ���"GET"β��
    u_char                           *schema_start;					//	schema��ʼ��ַ�����磺http://www.baidu.com�е�http��ʼ����
    u_char                           *schema_end;					//	schema������ַ�����磺http://www.baidu.com�е�httpβ����
    u_char                           *host_start;					//	����host��ʼ��ַ(www.baidu.com��ʼλ��)
    u_char                           *host_end;						//	����host������ַ(www.baidu.com����λ��)
    u_char                           *port_start;					//	����port��ʼ��ַ(http://www.baidu.com:80/��80��ʼλ��)
    u_char                           *port_end;						//	����port������ַ(http://www.baidu.com:80/��80����λ��)

    unsigned                          http_minor:16;				//	����ͷ�е�httpЭ��α���(e.g. http/1.0�е�0)
    unsigned                          http_major:16;				//	����ͷ�е�httpЭ��������(e.g. http/1.0�е�1)
};			//	end ngx_http_request_s


typedef struct {
    ngx_http_posted_request_t         terminal_posted_request;
#if (NGX_HAVE_AIO_SENDFILE)
    u_char                            aio_preload;
#endif
} ngx_http_ephemeral_t;


extern ngx_http_header_t       ngx_http_headers_in[];
extern ngx_http_header_out_t   ngx_http_headers_out[];


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
