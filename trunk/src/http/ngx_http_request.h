
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_MAX_URI_CHANGES           10						//	最大URI的重定向次数
#define NGX_HTTP_MAX_SUBREQUESTS           200

/* must be 2^n */
#define NGX_HTTP_LC_HEADER_LEN             32


#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
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
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
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


#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0			//	未使用到
#define NGX_HTTP_WRITE_BUFFERED            0x10			//	这个表示在最终的write filter中被buffered
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
    ngx_list_t                        headers;						//	存放请求头中的header name, 在函数 ngx_http_process_request_headers（）中设置

    ngx_table_elt_t                  *host;
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *if_unmodified_since;
    ngx_table_elt_t                  *user_agent;
    ngx_table_elt_t                  *referer;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_type;

    ngx_table_elt_t                  *range;
    ngx_table_elt_t                  *if_range;

    ngx_table_elt_t                  *transfer_encoding;
    ngx_table_elt_t                  *expect;						//	request header field "Expect: 100-continue"

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                  *accept_encoding;
    ngx_table_elt_t                  *via;
#endif

    ngx_table_elt_t                  *authorization;

    ngx_table_elt_t                  *keep_alive;					//	client发送的request请求头中包含的"Keep-alive:"域

#if (NGX_HTTP_PROXY || NGX_HTTP_REALIP || NGX_HTTP_GEO)
    ngx_table_elt_t                  *x_forwarded_for;
#endif

#if (NGX_HTTP_REALIP)
    ngx_table_elt_t                  *x_real_ip;
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

    ngx_str_t                         server;						//	==host
    off_t                             content_length_n;
    time_t                            keep_alive_n;

    unsigned                          connection_type:2;			//	客户端请求类型（close或keepalive（http1.1 keepalive））
    unsigned                          msie:1;
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
} ngx_http_headers_in_t;

/* 
 *	[analy]	定义了所有可以设置的HTTP Response Header信息, 这里并不包含所有HTTP头信息 
 */	
typedef struct {
    ngx_list_t                        headers;							//	list of ngx_table_elt_t

    ngx_uint_t                        status;							//	response status code (e.g. 状态码：200)
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
    ngx_str_t                         content_type;						//	用于 content_type域 （服务器发送内容的类型和编码类型）
    ngx_str_t                         charset;
    u_char                           *content_type_lowcase;
    ngx_uint_t                        content_type_hash;

    ngx_array_t                       cache_control;

    off_t                             content_length_n;					//	用于response body length
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

    void                            **ctx;
    void                            **main_conf;
    void                            **srv_conf;
    void                            **loc_conf;

    ngx_http_event_handler_pt         read_event_handler;						//	仅在 ngx_http_request_handler（） 中调用， ngx_http_request_handler（）在事件可读或可写是触发
    ngx_http_event_handler_pt         write_event_handler;						//	仅在 ngx_http_request_handler（） 中调用

#if (NGX_HTTP_CACHE)
    ngx_http_cache_t                 *cache;
#endif

    ngx_http_upstream_t              *upstream;
    ngx_array_t                      *upstream_states;
                                         /* of ngx_http_upstream_state_t */

    ngx_pool_t                       *pool;
    ngx_buf_t                        *header_in;					/* [analy]	调用recv等函数读取到的header信息的缓存，通过这个缓存对header进行分析 */

    ngx_http_headers_in_t             headers_in;					//	请求header的结构体
    ngx_http_headers_out_t            headers_out;

    ngx_http_request_body_t          *request_body;

    time_t                            lingering_time;
    time_t                            start_sec;
    ngx_msec_t                        start_msec;

    ngx_uint_t                        method;						//	请求行中的method值（NGX_HTTP_GET、NGX_HTTP_PUT、NGX_HTTP_POST）
    ngx_uint_t                        http_version;					//	请求头中主次版本号的拼装（e.g. http1.1 = 1001)

    ngx_str_t                         request_line;					//	请求行的内容 (e.g. "GET / HTTP/1.1")
    ngx_str_t                         uri;							//	请求行中uri部分(e.g. "/", 就一个字节)
    ngx_str_t                         args;
    ngx_str_t                         exten;
    ngx_str_t                         unparsed_uri;					//	备份请求行中原始的uri（uri有复合类型的）

    ngx_str_t                         method_name;					//	请求行中的method字符串值（GET、PUT、POST）
    ngx_str_t                         http_protocol;				//	请求行中的http协议版本字符串(e.g. "HTTP/1.1")

	ngx_chain_t                      *out;							//	这个chain保存的是上一次还没有被发完的buf，这样每次我们接收到新的chain的话，
																	//	就需要将新的chain连接到老的out chain上，然后再发出去。 
    ngx_http_request_t               *main;
    ngx_http_request_t               *parent;
    ngx_http_postponed_request_t     *postponed;
    ngx_http_post_subrequest_t       *post_subrequest;
    ngx_http_posted_request_t        *posted_requests;

    ngx_http_virtual_names_t         *virtual_names;

    ngx_int_t                         phase_handler;				//	在运行phase中的handler时，用此字段标识phase中下一个要执行的handler的下标
    ngx_http_handler_pt               content_handler;				//	有些特殊？？？？？？
    ngx_uint_t                        access_code;

	/* 变量在每个请求中的值是不一样的，也就是说变量是请求相关的
	 所以在ngx_http_request_s 中有一个变量数组，主要用于缓存当前请求的变量结果
	 从而可以避免一个变量的多次计数，计算过一次的变量就不用再计算了
	 但里面保存的一定是索引变量的值，是否缓存，也要由变量的特性来决定 */
    ngx_http_variable_value_t        *variables;					//	array of ngx_http_variable_value_t

#if (NGX_PCRE)
    ngx_uint_t                        ncaptures;
    int                              *captures;
    u_char                           *captures_data;
#endif

    size_t                            limit_rate;					//	限速速率，根据ngx_http_core_loc_conf_t->limit_rate值设置（ngx_http_update_location_config()函数中设置）

    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;					//	消息头长度（在 ngx_http_header_filter（）函数中有设置）

    off_t                             request_length;				//	请求头的长度

    ngx_uint_t                        err_status;

    ngx_http_connection_t            *http_connection;

    ngx_http_log_handler_pt           log_handler;

    ngx_http_cleanup_t               *cleanup;

    unsigned                          subrequests:8;				//	subrequests的最大次数（ngx_http_init_request()函数中初始化）
    unsigned                          count:8;
    unsigned                          blocked:8;

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

    unsigned                          invalid_header:1;					//	标识当前解析的请求头是否有效（单行中的）

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;					//	??????????
    unsigned                          valid_unparsed_uri:1;				//	????????????
    unsigned                          uri_changed:1;					//	当前的uri是否被重定向，是否改变
    unsigned                          uri_changes:4;					//	uri可以重定向的最大次数，最大10次（ngx_http_init_request()函数中初始化）

    unsigned                          request_body_in_single_buf:1;
    unsigned                          request_body_in_file_only:1;
    unsigned                          request_body_in_persistent_file:1;
    unsigned                          request_body_in_clean_file:1;
    unsigned                          request_body_file_group_access:1;
    unsigned                          request_body_file_log_level:3;

    unsigned                          subrequest_in_memory:1;
    unsigned                          waited:1;

#if (NGX_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (NGX_HTTP_GZIP)
    unsigned                          gzip_tested:1;					//	gzip相关的设置
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
    unsigned                          plain_http:1;					//	用在ssl中
    unsigned                          chunked:1;					//	是否为chunked传输
    unsigned                          header_only:1;				//	是否仅有消息头
    unsigned                          keepalive:1;					//	是否为keepalive连接( ngx_http_handler()函数中根据 r->headers_in.connection_type类型确定 )
    unsigned                          lingering_close:1;
    unsigned                          discard_body:1;
    unsigned                          internal:1;					//	标示此请求是内部跳转 （ngx_http_internal_redirect()函数中设置）
    unsigned                          error_page:1;
    unsigned                          ignore_content_encoding:1;
    unsigned                          filter_finalize:1;
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;
    unsigned                          header_sent:1;
    unsigned                          expect_tested:1;
    unsigned                          root_tested:1;
    unsigned                          done:1;
    unsigned                          logged:1;

    unsigned                          buffered:4;

    unsigned                          main_filter_need_in_memory:1;		//	???
    unsigned                          filter_need_in_memory:1;
    unsigned                          filter_need_temporary:1;
    unsigned                          allow_ranges:1;

#if (NGX_STAT_STUB)
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
#endif

    /* used to parse HTTP headers */

    ngx_uint_t                        state;							//	在解析request line时，由于client一次未发送完全，导致没有全部解析完毕，
																		//	备份的解析当前位置 ngx_http_parse_request_line() 函数中进行设置

    ngx_uint_t                        header_hash;						//	header name的hash值
    ngx_uint_t                        lowcase_index;					//	应该是header name的字符个数
    u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN];	//	小写的 header name字符串（e.g. "user-agent"）

    u_char                           *header_name_start;				//	指向请求头中header name开始（e.g. "User-Agent: curl/7.20.0"）
    u_char                           *header_name_end;					//	指向请求头中header name结束（e.g. "User-Agent"）
    u_char                           *header_start;						//	指向请求头中header value的起始位置 （e.g. "curl/7.20.0"）
    u_char                           *header_end;						//	指向请求头中header value的结束位置 （e.g. "curl/7.20.0"）

    /*
     * a memory that can be reused after parsing a request line
     * via ngx_http_ephemeral_t
     */

    u_char                           *uri_start;					/* [analy]	uri开始地址 */
    u_char                           *uri_end;
    u_char                           *uri_ext;						//	?????????????
    u_char                           *args_start;
    u_char                           *request_start;				/* [analy]	请求的开始地址-> "GET .. ... .. " */
    u_char                           *request_end;					/* [analy]	请求行的结束地址		 */
    u_char                           *method_end;					/* [analy]	method的结束地址-> "GET URL VER", 字符串"GET"尾部 */
    u_char                           *schema_start;					/* [analy]	schema开始地址（例如：http://www.baidu.com中的http开始处） */
    u_char                           *schema_end;					/* [analy]	schema结束地址（例如：http://www.baidu.com中的http尾处） */
    u_char                           *host_start;					/* [analy]	设置host开始地址(www.baidu.com开始位置) */
    u_char                           *host_end;						/* [analy]	设置host结束地址(www.baidu.com结束位置) */
    u_char                           *port_start;					/* [analy]	设置port开始地址(http://www.baidu.com:80/在80开始位置) */
    u_char                           *port_end;						/* [analy]	设置port结束地址(http://www.baidu.com:80/在80结束位置) */

    unsigned                          http_minor:16;				//	请求头中的http协议次本号
    unsigned                          http_major:16;				//	请求头中的http协议主本号
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
