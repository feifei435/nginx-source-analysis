
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
	模块功能:			此模块是第一个执行的header filter; 
	模块使用指令:		"if_modified_since"进行检查
	首先检查;
		1. 响应状态码(r->headers_out.status)不等于200时，不执行此模块
		2. "非根请求" 不执行此模块;
		3. "r->headers_out.last_modified_time"字段如果未被赋值(说明客户端请求的是服务器端的一个文件)，不执行此模块
	再检查:
		检查请求头中是否包含 "if_unmodified_since" 和 "if_modified_since" 字段
	

*/


static ngx_int_t ngx_http_test_precondition(ngx_http_request_t *r);
static ngx_int_t ngx_http_test_not_modified(ngx_http_request_t *r);
static ngx_int_t ngx_http_not_modified_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_not_modified_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_not_modified_filter_init,     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_not_modified_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_not_modified_filter_module_ctx, /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

/*
 *	[analy]	对请求头中 "if_unmodified_since" 和 "if_modified_since" 字段的检查
 */
static ngx_int_t
ngx_http_not_modified_header_filter(ngx_http_request_t *r)
{
    if (r->headers_out.status != NGX_HTTP_OK
        || r != r->main
        || r->headers_out.last_modified_time == -1)				//	响应状态码不是200、进行处理的不是主请求、last_modified_time=
    {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_in.if_unmodified_since) {					//	请求头中包含 "If-Unmodified-Since"
        return ngx_http_test_precondition(r);
    }

    if (r->headers_in.if_modified_since) {						//	请求头中包含 "if_modified_since"
        return ngx_http_test_not_modified(r);	
    }

    return ngx_http_next_header_filter(r);
}

/*
 *	[analy]	检查请求头中"if_unmodified_since"字段时间与文件的最后修改时间
 */
static ngx_int_t
ngx_http_test_precondition(ngx_http_request_t *r)
{
    time_t  iums;

    iums = ngx_http_parse_time(r->headers_in.if_unmodified_since->value.data,
                               r->headers_in.if_unmodified_since->value.len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "http iums:%d lm:%d", iums, r->headers_out.last_modified_time);

    if (iums >= r->headers_out.last_modified_time) {
        return ngx_http_next_header_filter(r);
    }

    return ngx_http_filter_finalize_request(r, NULL,
                                            NGX_HTTP_PRECONDITION_FAILED);
}

/*
 *	[analy]	检查请求头中"if_modified_since"字段时间与文件的最后修改时间
 */
static ngx_int_t
ngx_http_test_not_modified(ngx_http_request_t *r)
{
    time_t                     ims;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	//	如果指令 "if_modified_since" 指定为off， 将不检查请求头 "if_modified_since" 的时间，直接执行下一个filter
    if (clcf->if_modified_since == NGX_HTTP_IMS_OFF) {					
        return ngx_http_next_header_filter(r);
    }

	//	转换if_modified_since的时间
    ims = ngx_http_parse_time(r->headers_in.if_modified_since->value.data,					//	e.g. "Wed, 04 Apr 2012 21:23:20 GMT"
                              r->headers_in.if_modified_since->value.len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ims:%d lm:%d", ims, r->headers_out.last_modified_time);

	//	请求头中"if modified since"时间与文件的最后修改时间不一致， 
	//	指令 "if_modified_since" 指定为 "精确匹配时" 或 请求头中的文件最后修改时间 < 服务器中的文件最后修改时间， 将执行下一个filter
    if (ims != r->headers_out.last_modified_time) {

        if (clcf->if_modified_since == NGX_HTTP_IMS_EXACT
            || ims < r->headers_out.last_modified_time)		
        {
            return ngx_http_next_header_filter(r);
        }
    }

	//	如果if modified since 返回的时间与服务器上文件最后修改时间相等则返回304
    r->headers_out.status = NGX_HTTP_NOT_MODIFIED;				//	304
    r->headers_out.status_line.len = 0;
    r->headers_out.content_type.len = 0;
    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);

    if (r->headers_out.content_encoding) {
        r->headers_out.content_encoding->hash = 0;
        r->headers_out.content_encoding = NULL;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_not_modified_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_not_modified_header_filter;

    return NGX_OK;
}
