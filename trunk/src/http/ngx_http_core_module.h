
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_SENDFILE           2


#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1


#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_LINGERING_ALWAYS       2


#define NGX_HTTP_IMS_OFF                0					//	指令 "if_modified_since" 使用(不检查请求头中的”If-Modified-Since)
#define NGX_HTTP_IMS_EXACT              1					//	exact：精确匹配
#define NGX_HTTP_IMS_BEFORE             2					//	before：文件修改时间应小于请求头中的”If-Modified-Since”时间


#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;
typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;


typedef struct {
    union {
        struct sockaddr        sockaddr;
        struct sockaddr_in     sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6    sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un     sockaddr_un;
#endif
        u_char                 sockaddr_data[NGX_SOCKADDRLEN];
    } u;

    socklen_t                  socklen;					//	sockaddr结构的长度

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;				//	是否使用通配符（ngx_url_t中的wildcard）
#if (NGX_HTTP_SSL)
    unsigned                   ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                   ipv6only:2;
#endif
    unsigned                   so_keepalive:2;

    int                        backlog;					//	backlog大小
    int                        rcvbuf;
    int                        sndbuf;
#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t                 deferred_accept;
#endif

    u_char                     addr[NGX_SOCKADDR_STRLEN + 1];		//	根据sockaddr结构转换格式为"192.168.124.129:8011"
} ngx_http_listen_opt_t;


typedef enum {
    NGX_HTTP_POST_READ_PHASE = 0,						//	读取请求阶段

    NGX_HTTP_SERVER_REWRITE_PHASE,						//	URI转换阶段（这个阶段主要是处理全局的(server block)的rewrite）

    NGX_HTTP_FIND_CONFIG_PHASE,							//	查找相应的配置来执行(这个阶段主要是通过uri来查找对应的location, 然后将uri和location的数据关联起来)
    NGX_HTTP_REWRITE_PHASE,								//	这个主要处理location的rewrite  
    NGX_HTTP_POST_REWRITE_PHASE,						//	post rewrite，这个主要是进行一些校验以及收尾工作，以便于交给后面的模块 

    NGX_HTTP_PREACCESS_PHASE,							//	比如流控这种类型的access就放在这个phase，也就是说它主要是进行一些比较粗粒度的access  

    NGX_HTTP_ACCESS_PHASE,								//	这个比如存取控制，权限验证就放在这个phase，一般来说处理动作是交给下面的模块做的.这个主要是做一些细粒度的access  
    NGX_HTTP_POST_ACCESS_PHASE,							//	一般来说当上面的access模块得到access_code之后就会由这个模块根据access_code来进行操作  

    NGX_HTTP_TRY_FILES_PHASE,							//	try_file模块，也就是对应配置文件中的try_files指令
    NGX_HTTP_CONTENT_PHASE,								//	内容处理模块，我们一般的handler都是处于这个模块  

    NGX_HTTP_LOG_PHASE									// [analy]	记录日志处理阶段，具体说明应当是请求完成后，关闭请求时处理
} ngx_http_phases;

typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;					//	phase中handler使用的类型


//	每个phase的checker类型函数指针; 参数2: 
typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,				
    ngx_http_phase_handler_t *ph);

struct ngx_http_phase_handler_s {
    ngx_http_phase_handler_pt  checker;
    ngx_http_handler_pt        handler;
    ngx_uint_t                 next;			//	指向下一个phase在数组中的元素下标或特定phase的下标(而不是同一phase的下一个handler)
};


typedef struct {
    ngx_http_phase_handler_t  *handlers;							//	phase中所有handler集合
    ngx_uint_t                 server_rewrite_index;				//	指向　NGX_HTTP_SERVER_REWRITE_PHASE　 阶段的索引号
    ngx_uint_t                 location_rewrite_index;				//	指向　NGX_HTTP_REWRITE_PHASE		　阶段的索引号
} ngx_http_phase_engine_t;


typedef struct {
    ngx_array_t                handlers;			//	每个数组元素都是一个 ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);函数
} ngx_http_phase_t;


typedef struct {
    ngx_array_t                servers;								// array of ngx_http_core_srv_conf_t

    ngx_http_phase_engine_t    phase_engine;

    ngx_hash_t                 headers_in_hash;						//	ngx_http_headers_in 静态数组的hash表

    ngx_hash_t                 variables_hash;						//	变量hash表(对variables_keys.keys中的变量进行hash计算得到)

    ngx_array_t                variables;							//	索引变量的数组		/* ngx_http_variable_t */
    ngx_uint_t                 ncaptures;

    ngx_uint_t                 server_names_hash_max_size;			//	参考配置指令
    ngx_uint_t                 server_names_hash_bucket_size;		//	参考配置指令

    ngx_uint_t                 variables_hash_max_size;				//	参考配置指令
    ngx_uint_t                 variables_hash_bucket_size;			//	参考配置指令

    ngx_hash_keys_arrays_t    *variables_keys;						//	变量hash数组（在 ngx_http_variables_add_core_vars（）函数中申请空间并初始化）

    ngx_array_t               *ports;								//	array of ngx_http_conf_port_t

    ngx_uint_t                 try_files;							//	使用了try_files指令时设置为1(ngx_http_core_try_files()中设置)			/* unsigned  try_files:1 */

    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
} ngx_http_core_main_conf_t;


typedef struct {
    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                 server_names;

    /* server ctx */
    ngx_http_conf_ctx_t        *ctx;							//	指向在ngx_http_core_server（）中申请的ctx

    ngx_str_t                   server_name;					//	是 server_names 数组中第一个服务器名称

    size_t                      connection_pool_size;			//	指令 "connection_pool_size" 为每个连接分配的内存池( 在函数ngx_http_add_listening()中赋值，赋值给ls->pool_size )
    size_t                      request_pool_size;				//	指令 "request_pool_size" 在处理请求时，所使用的内存池大小，默认是4K
	size_t                      client_header_buffer_size;		//	指令 "client_header_buffer_size" 指定客户端请求头部的缓冲区大小, 绝大多数情况下一个请求头不会大于1k
																//					不过如果有来自于wap客户端的较大的cookie它可能会大于1k设置处理从客户端过来的请求buffer大小
	
    ngx_bufs_t                  large_client_header_buffers;	//	指定客户端一些比较大的请求头使用的缓冲区数量和大小(large_client_header_buffers指令)

    ngx_msec_t                  client_header_timeout;			//	指令 "client_header_timeout" 指定读取客户端请求头标题的超时时间，默认60s

    ngx_flag_t                  ignore_invalid_headers;			//	指令 "ignore_invalid_headers" 是否忽略无效的请求头
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;			//	是否允许在header的字段中带下划线(underscores_in_headers指令)

    unsigned                    listen:1;						//	此字段是否说明 server{...} 块中 有listen指令
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif

    ngx_http_core_loc_conf_t  **named_locations;				//	命名匹配location数组(ngx_http_init_locations()函数中赋值)
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;

    ngx_http_virtual_names_t  *virtual_names;

#if (NGX_HTTP_SSL)
    ngx_uint_t                 ssl;   /* unsigned  ssl:1; */
#endif
} ngx_http_addr_conf_t;


typedef struct {
    in_addr_t                  addr;
    ngx_http_addr_conf_t       conf;
} ngx_http_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_http_addr_conf_t       conf;
} ngx_http_in6_addr_t;

#endif


typedef struct {
    /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
    void                      *addrs;
    ngx_uint_t                 naddrs;
} ngx_http_port_t;


typedef struct {
    ngx_int_t                  family;
    in_port_t                  port;
    ngx_array_t                addrs;     /* array of ngx_http_conf_addr_t */
} ngx_http_conf_port_t;


typedef struct {
    ngx_http_listen_opt_t      opt;

    ngx_hash_t                 hash;
    ngx_hash_wildcard_t       *wc_head;
    ngx_hash_wildcard_t       *wc_tail;

#if (NGX_PCRE)
    ngx_uint_t                 nregex;
    ngx_http_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;
    ngx_array_t                servers;  /* array of ngx_http_core_srv_conf_t */
} ngx_http_conf_addr_t;


struct ngx_http_server_name_s {
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;
#endif
    ngx_http_core_srv_conf_t  *server;					//	server层的创建的srv_conf			/* virtual name server conf */
    ngx_str_t                  name;					//	server_name指令指定的参数名称
};


typedef struct {
    ngx_int_t                  status;
    ngx_int_t                  overwrite;
    ngx_http_complex_value_t   value;
    ngx_str_t                  args;
} ngx_http_err_page_t;


typedef struct {
    ngx_array_t               *lengths;					//	try_files指令变量使用
    ngx_array_t               *values;					//	try_files指令变量使用
    ngx_str_t                  name;					//	try_files指令的参数

    unsigned                   code:10;
    unsigned                   test_dir:1;				//	是否为目录
} ngx_http_try_file_t;


struct ngx_http_core_loc_conf_s {
    ngx_str_t     name;          /* location name */		//	location-url

#if (NGX_PCRE)
    ngx_http_regex_t  *regex;								//	正则匹配（"~" 或 "~*"）
#endif

    unsigned      noname:1;									/* "if () {}" block or limit_except */ //	nginx会把if 指令配置也看做一个location，即noname类型。
    unsigned      lmt_excpt:1;								//	location中有“limit_except”指令时为1
    unsigned      named:1;									//	命名匹配("@") {子location不允许为命名匹配}

    unsigned      exact_match:1;							//	精确匹配("=")
    unsigned      noregex:1;								//	非正则匹配( " ^~ " )

	/* 此字段在以下几个模块中被赋值
		ngx_http_fastcgi_module.c
		ngx_http_memcached_module.c
		ngx_http_proxy_module.c
		ngx_http_scgi_module.c
		ngx_http_uwsgi_module.c */
    unsigned      auto_redirect:1;

#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
#if (NGX_HTTP_DEGRADATION)
    unsigned      gzip_disable_degradation:2;
#endif
#endif

    ngx_http_location_tree_node_t   *static_locations;		//	字符串匹配的三叉排序树
#if (NGX_PCRE)
    ngx_http_core_loc_conf_t       **regex_locations;		//	正则匹配的location数组(ngx_http_init_locations()函数中赋值)
#endif

    /* pointer to the modules' loc_conf */
    void        **loc_conf;									//	指向所有模块的loc_conf

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    ngx_http_handler_pt  handler;							//	此handler被设置后将被赋值给 r->content_handler

    /* location name length for inclusive location with inherited alias */
    size_t        alias;									//	"alias"指令时，长度等于location的name长度."root"指令时，长度等于0
    ngx_str_t     root;										//	用于存放root和alias指令未解析的参数					/* root, alias */
    ngx_str_t     post_action;								//	指令 "post_action" 指定为当前完成请求的子请求定义一个URI。

    ngx_array_t  *root_lengths;								//	root和alias指令的参数中使用变量后，将变量和常量字符串的长度存于此链表中
    ngx_array_t  *root_values;								//	root和alias指令的参数中使用变量后，将变量和常量字符串的解析后的字符串存于此链表中

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;								//	指令 "default_type" 指定的正文的类型，默认是text/plain

    off_t         client_max_body_size;						//  指令 "client_max_body_size" 指定允许客户端连接的最大请求实体大小，它出现在请求头部的Content-Length字段
    off_t         directio;									//	指令 "directio"				指定是否开启DIRECT_IO, 默认是关闭的；如果未指定off时，此值保存direct_io的大小
    off_t         directio_alignment;						//	指令 "directio_alignment"	指定在使用direct io时的对齐长度

    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;								/* send_lowat */
    size_t        postpone_output;         /* postpone_output		延迟发送的阀值，默认1460 */
    size_t        limit_rate;              // limit_rate 指令限制将应答传送到客户端的速度，单位为字节/秒
    size_t        limit_rate_after;        /* limit_rate_after */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk    sendfile()系统调用传输的数据统计限制 */
    size_t        read_ahead;              /* read_ahead */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            //	指令 "send_timeout" 默认60s
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout指令的第一个参数使用此字段，服务器主动关闭连接的超时时间， 默认是75000
													参数的第一个值指定了客户端与服务器长连接的超时时间，超过这个时间，服务器将关闭连接。
													参数的第二个值（可选）指定了应答头中Keep-Alive: timeout=time的time值，这个值可以使一些浏览器知道什么时候关闭连接，
													以便服务器不用重复关闭，如果不指定这个参数，nginx不会在应答头中发送Keep-Alive信息。
										   */

    ngx_msec_t    lingering_time;          /* lingering_time 指令指定，参数指定的时间单位为秒，在内存中存放的是毫秒（msec) */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout 指令指定, 参数指定的时间单位为秒，在内存中存放的是毫秒（msec)  */


    ngx_msec_t    resolver_timeout;        //	指令 "resolver_timeout" 默认30s
    ngx_resolver_t  *resolver;             //	指令 "resolver" 被使用时，申请的结构空间

    time_t        keepalive_header;        // keepalive_timeout指令的第二个参数使用
										   // 决定是否在响应头中发送包含timeout=time的值
										   

    ngx_uint_t    keepalive_requests;      // keepalive_requests指令指定服务器保持长连接的请求数???????????????????????。默认是100
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close 指令默认是开启的，指定socket的SO_LINGER选项 */
    ngx_uint_t    if_modified_since;       // 指令 "if_modified_since" 指定将文件最后修改时间与请求头中的”If-Modified-Since”时间相比较的方式，默认exact
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only;			// client_body_in_file_only 指令打开后将始终保存request的body信息

	ngx_flag_t    client_body_in_single_buffer;     // client_body_in_singe_buffer 指定是否将客户端连接请求完整的放入一个缓冲区，当使用变量$request_body时推荐使用这个指令以减少复制操作。
													//	如果无法将一个请求放入单个缓冲区，将会被放入磁盘。
    ngx_flag_t    internal;										 // 指令 "internal"		指定某个location只能被“内部的”请求调用，外部的调用请求会返回”Not found” (404)
    ngx_flag_t    sendfile;										 // 指令 "sendfile"		指定在发送时是否使用sendfile()系统调用

#if (NGX_HAVE_FILE_AIO)
    ngx_flag_t    aio;                     /* aio */
#endif

    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             // 指令 "tcp_nodelay" 指定是否关闭Nagle算法
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh: 指令允许或拒绝为MSIE发布一个refresh而不是做一次redirect */
    ngx_flag_t    log_not_found;           /* log_not_found: 指令指定是否将一些文件没有找到的错误信息写入error_log指定的文件中 */
    ngx_flag_t    log_subrequest;          /* log_subrequest */
    ngx_flag_t    recursive_error_pages;   /* 指令"recursive_error_pages" 指定启用除第一条error_page指令以外其他的error_page */
    ngx_flag_t    server_tokens;           /* server_tokens: 是否在错误页面和服务器头中输出nginx版本信息 */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */

#if (NGX_HTTP_GZIP)
    ngx_flag_t    gzip_vary;               /* gzip_vary */

    ngx_uint_t    gzip_http_version;       /* gzip_http_version */
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (NGX_HAVE_OPENAT)
	ngx_uint_t    disable_symlinks;							//	存放指令"disable_symlinks" 的指定参数标记	
																
    ngx_http_complex_value_t  *disable_symlinks_from;		//	指令"disable_symlinks" 使用了from参数： Determines how symbolic links should be treated when opening files:
															//	指向"disable_symlinks" 指令申请的ngx_http_complex_value_t结构（函数中ngx_http_disable_symlinks()设置）
#endif	

    ngx_array_t  *error_pages;					/* error_page */
    ngx_http_try_file_t    *try_files;			//	ngx_http_core_try_files()函数中设置	/* try_files */

    ngx_path_t   *client_body_temp_path;		/* client_body_temp_path */

    ngx_open_file_cache_t  *open_file_cache;	//	指令"open_file_cache"不为off时，将创建一个 ngx_open_file_cache_t 类型结构(ngx_http_core_open_file_cache()函数中创建)
    time_t        open_file_cache_valid;		//	这个指令指定了何时需要检查open_file_cache中缓存项目的有效信息。 （默认60s）
    ngx_uint_t    open_file_cache_min_uses;		//	这个指令指定了在open_file_cache指令无效的参数中一定的时间范围内，
												//	可以使用的最小文件数，如果使用更大的值，文件描述符在cache中总是打开状态。 
    ngx_flag_t    open_file_cache_errors;		//	这个指令指定是否在搜索一个文件时记录cache错误，默认是关闭状态
    ngx_flag_t    open_file_cache_events;		//	默认是0；?????????

    ngx_log_t    *error_log;

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

    ngx_queue_t  *locations;					//	ngx_http_location_queue_t 的队列头，server层和location层均有自己的队列
												//	根据指令"if和location"所在位置的不同，如果在server {...}中时location队列挂接到server层，
												//	如果在location {...} 内时为location队列挂接到location层。

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};


typedef struct {
    ngx_queue_t                      queue;					//	队列的节点
    ngx_http_core_loc_conf_t        *exact;					//	??????不清楚作用
    ngx_http_core_loc_conf_t        *inclusive;				//	??????不清楚作用
    ngx_str_t                       *name;					//	指向ngx_http_core_loc_conf_t的name字段(location指令的url)
    u_char                          *file_name;				//	解析的配置文件完整路径（/usr/local/nginx/conf/nginx.conf）
    ngx_uint_t                       line;					//	配置文件中正在解析的行NUM
    ngx_queue_t                      list;					//	??????不清楚作用
} ngx_http_location_queue_t;


struct ngx_http_location_tree_node_s {
    ngx_http_location_tree_node_t   *left;
    ngx_http_location_tree_node_t   *right;
    ngx_http_location_tree_node_t   *tree;

    ngx_http_core_loc_conf_t        *exact;
    ngx_http_core_loc_conf_t        *inclusive;

    u_char                           auto_redirect;
    u_char                           len;
    u_char                           name[1];
};


void ngx_http_core_run_phases(ngx_http_request_t *r);
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_try_files_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);


void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
void ngx_http_set_exten(ngx_http_request_t *r);
ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_http_complex_value_t *cv);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
#if (NGX_HTTP_GZIP)
ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
#endif


ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **sr,
    ngx_http_post_subrequest_t *psr, ngx_uint_t flags);
ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);


ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);


typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_set_disable_symlinks(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;

extern ngx_str_t  ngx_http_core_get_method;


#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }
                                                                              \
#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
