
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*		
		模块功能:			此模块是第一个执行的header filter; 
		模块指令:			"expires:"、"add_header"
		逻辑说明;			
			首先检查是否使用"expires"和"add_header"两个指定， 未使用将执行下一个filter
			然后分别处理两条指令
*/


typedef struct ngx_http_header_val_s  ngx_http_header_val_t;

typedef ngx_int_t (*ngx_http_set_header_pt)(ngx_http_request_t *r,
    ngx_http_header_val_t *hv, ngx_str_t *value);


typedef struct {
    ngx_str_t                  name;
    ngx_uint_t                 offset;
    ngx_http_set_header_pt     handler;
} ngx_http_set_header_t;


struct ngx_http_header_val_s {
    ngx_http_complex_value_t   value;
    ngx_uint_t                 hash;
    ngx_str_t                  key;
    ngx_http_set_header_pt     handler;
    ngx_uint_t                 offset;
};


#define NGX_HTTP_EXPIRES_OFF       0
#define NGX_HTTP_EXPIRES_EPOCH     1
#define NGX_HTTP_EXPIRES_MAX       2
#define NGX_HTTP_EXPIRES_ACCESS    3
#define NGX_HTTP_EXPIRES_MODIFIED  4
#define NGX_HTTP_EXPIRES_DAILY     5


typedef struct {
    ngx_uint_t               expires;				//	指令"expires"的类型，默认是off
    time_t                   expires_time;			//	指令"expires"指定的过期时间
    ngx_array_t             *headers;				//	array of ngx_http_header_val_t
} ngx_http_headers_conf_t;


static ngx_int_t ngx_http_set_expires(ngx_http_request_t *r,
    ngx_http_headers_conf_t *conf);
static ngx_int_t ngx_http_add_cache_control(ngx_http_request_t *r,
    ngx_http_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_last_modified(ngx_http_request_t *r,
    ngx_http_header_val_t *hv, ngx_str_t *value);

static void *ngx_http_headers_create_conf(ngx_conf_t *cf);
static char *ngx_http_headers_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_headers_filter_init(ngx_conf_t *cf);
static char *ngx_http_headers_expires(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_headers_add(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_http_set_header_t  ngx_http_set_headers[] = {

    { ngx_string("Cache-Control"), 0, ngx_http_add_cache_control },

    { ngx_string("Last-Modified"),
                 offsetof(ngx_http_headers_out_t, last_modified),
                 ngx_http_set_last_modified },

    { ngx_null_string, 0, NULL }
};


static ngx_command_t  ngx_http_headers_filter_commands[] = {

	/*
		使用本指令可以控制HTTP应答中的“Expires”和“Cache-Control”的头标， （起到控制页面缓存的作用）
		可以在time值中使用正数或负数。“Expires”头标的值将通过当前系统时间加上您设定的 time 值来获得。
		epoch 指定“Expires”的值为 1 January, 1970, 00:00:01 GMT
		max 指定“Expires”的值为 31 December 2037 23:59:59 GMT，“Cache-Control”的值为10年
		-1 指定“Expires”的值为 服务器当前时间 -1s,即永远过期 

		expires 两种配置方式:
			expires [ modified ] time
			expires epoch | max | off

		example:
			expires    24h;
			expires    modified +24h;
			expires    @24h;
			expires    0;
			expires    -1;
			expires    epoch|max|off;

	*/
    { ngx_string("expires"),				
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE12,
      ngx_http_headers_expires,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

	/* 
	 *	
	 */
    { ngx_string("add_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE2,
      ngx_http_headers_add,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

      ngx_null_command
};


static ngx_http_module_t  ngx_http_headers_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_headers_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_headers_create_conf,          /* create location configuration */
    ngx_http_headers_merge_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_headers_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_headers_filter_module_ctx,   /* module context */
    ngx_http_headers_filter_commands,      /* module directives */
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


static ngx_int_t
ngx_http_headers_filter(ngx_http_request_t *r)
{
    ngx_str_t                 value;
    ngx_uint_t                i;
    ngx_http_header_val_t    *h;
    ngx_http_headers_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_headers_filter_module);

    if ((conf->expires == NGX_HTTP_EXPIRES_OFF && conf->headers == NULL)			//	未使用"expires"和"add_header"两个指定时， 将执行下一个filter
        || r != r->main																//	当前请求不是根请求
        || (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_NO_CONTENT
            && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != NGX_HTTP_MOVED_PERMANENTLY
            && r->headers_out.status != NGX_HTTP_MOVED_TEMPORARILY
            && r->headers_out.status != NGX_HTTP_SEE_OTHER
            && r->headers_out.status != NGX_HTTP_NOT_MODIFIED
            && r->headers_out.status != NGX_HTTP_TEMPORARY_REDIRECT))
    {
        return ngx_http_next_header_filter(r);
    }


	//	处理"expires"指令
    if (conf->expires != NGX_HTTP_EXPIRES_OFF) {									//	当使用了expires指令时
        if (ngx_http_set_expires(r, conf) != NGX_OK) {			//	添加"Expires"和"Cache-Control"头到响应头中
            return NGX_ERROR;
        }
    }

	//	处理"add_header"指令
    if (conf->headers) {
        h = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {

            if (ngx_http_complex_value(r, &h[i].value, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (h[i].handler(r, &h[i], &value) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_set_expires(ngx_http_request_t *r, ngx_http_headers_conf_t *conf)
{
    size_t            len;
    time_t            now, expires_time, max_age;
    ngx_uint_t        i;
    ngx_table_elt_t  *expires, *cc, **ccp;

    expires = r->headers_out.expires;

    if (expires == NULL) {

        expires = ngx_list_push(&r->headers_out.headers);
        if (expires == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.expires = expires;

        expires->hash = 1;
        ngx_str_set(&expires->key, "Expires");
    }

    len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");
    expires->value.len = len - 1;

    ccp = r->headers_out.cache_control.elts;

    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ccp = ngx_array_push(&r->headers_out.cache_control);
        if (ccp == NULL) {
            return NGX_ERROR;
        }

        cc = ngx_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            return NGX_ERROR;
        }

        cc->hash = 1;
        ngx_str_set(&cc->key, "Cache-Control");
        *ccp = cc;

    } else {
        for (i = 1; i < r->headers_out.cache_control.nelts; i++) {
            ccp[i]->hash = 0;
        }

        cc = ccp[0];
    }

    if (conf->expires == NGX_HTTP_EXPIRES_EPOCH) {
        expires->value.data = (u_char *) "Thu, 01 Jan 1970 00:00:01 GMT";
        ngx_str_set(&cc->value, "no-cache");
        return NGX_OK;
    }

    if (conf->expires == NGX_HTTP_EXPIRES_MAX) {
        expires->value.data = (u_char *) "Thu, 31 Dec 2037 23:55:55 GMT";
        /* 10 years */
        ngx_str_set(&cc->value, "max-age=315360000");
        return NGX_OK;
    }

    expires->value.data = ngx_pnalloc(r->pool, len);
    if (expires->value.data == NULL) {
        return NGX_ERROR;
    }

    if (conf->expires_time == 0 && conf->expires != NGX_HTTP_EXPIRES_DAILY) {
        ngx_memcpy(expires->value.data, ngx_cached_http_time.data,
                   ngx_cached_http_time.len + 1);
        ngx_str_set(&cc->value, "max-age=0");
        return NGX_OK;
    }

    now = ngx_time();

    if (conf->expires == NGX_HTTP_EXPIRES_DAILY) {
        expires_time = ngx_next_time(conf->expires_time);
        max_age = expires_time - now;

    } else if (conf->expires == NGX_HTTP_EXPIRES_ACCESS
               || r->headers_out.last_modified_time == -1)
    {
        expires_time = now + conf->expires_time;
        max_age = conf->expires_time;

    } else {
        expires_time = r->headers_out.last_modified_time + conf->expires_time;
        max_age = expires_time - now;
    }

    ngx_http_time(expires->value.data, expires_time);

    if (conf->expires_time < 0 || max_age < 0) {
        ngx_str_set(&cc->value, "no-cache");
        return NGX_OK;
    }

    cc->value.data = ngx_pnalloc(r->pool,
                                 sizeof("max-age=") + NGX_TIME_T_LEN + 1);
    if (cc->value.data == NULL) {
        return NGX_ERROR;
    }

    cc->value.len = ngx_sprintf(cc->value.data, "max-age=%T", max_age)
                    - cc->value.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_add_header(ngx_http_request_t *r, ngx_http_header_val_t *hv,
    ngx_str_t *value)
{
    ngx_table_elt_t  *h;

    if (value->len) {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = hv->hash;
        h->key = hv->key;
        h->value = *value;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_add_cache_control(ngx_http_request_t *r, ngx_http_header_val_t *hv,
    ngx_str_t *value)
{
    ngx_table_elt_t  *cc, **ccp;

    ccp = r->headers_out.cache_control.elts;

    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ccp = ngx_array_push(&r->headers_out.cache_control);
    if (ccp == NULL) {
        return NGX_ERROR;
    }

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc == NULL) {
        return NGX_ERROR;
    }

    cc->hash = 1;
    ngx_str_set(&cc->key, "Cache-Control");
    cc->value = *value;

    *ccp = cc;

    return NGX_OK;
}


static ngx_int_t
ngx_http_set_last_modified(ngx_http_request_t *r, ngx_http_header_val_t *hv,
    ngx_str_t *value)
{
    ngx_table_elt_t  *h, **old;

    if (hv->offset) {
        old = (ngx_table_elt_t **) ((char *) &r->headers_out + hv->offset);

    } else {
        old = NULL;
    }

    r->headers_out.last_modified_time = -1;

    if (old == NULL || *old == NULL) {

        if (value->len == 0) {
            return NGX_OK;
        }

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

    } else {
        h = *old;

        if (value->len == 0) {
            h->hash = 0;
            return NGX_OK;
        }
    }

    h->hash = hv->hash;
    h->key = hv->key;
    h->value = *value;

    return NGX_OK;
}


static void *
ngx_http_headers_create_conf(ngx_conf_t *cf)
{
    ngx_http_headers_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_headers_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->headers = NULL;
     *     conf->expires_time = 0;
     */

    conf->expires = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_headers_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_headers_conf_t *prev = parent;
    ngx_http_headers_conf_t *conf = child;

    if (conf->expires == NGX_CONF_UNSET_UINT) {
        conf->expires = prev->expires;
        conf->expires_time = prev->expires_time;

        if (conf->expires == NGX_CONF_UNSET_UINT) {
            conf->expires = NGX_HTTP_EXPIRES_OFF;
        }
    }

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_headers_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_headers_filter;

    return NGX_OK;
}


static char *
ngx_http_headers_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_headers_conf_t *hcf = conf;

    ngx_uint_t   minus, n;
    ngx_str_t   *value;

    if (hcf->expires != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        if (ngx_strcmp(value[1].data, "epoch") == 0) {
            hcf->expires = NGX_HTTP_EXPIRES_EPOCH;
            return NGX_CONF_OK;
        }

        if (ngx_strcmp(value[1].data, "max") == 0) {
            hcf->expires = NGX_HTTP_EXPIRES_MAX;
            return NGX_CONF_OK;
        }

        if (ngx_strcmp(value[1].data, "off") == 0) {
            hcf->expires = NGX_HTTP_EXPIRES_OFF;
            return NGX_CONF_OK;
        }

        hcf->expires = NGX_HTTP_EXPIRES_ACCESS;

        n = 1;

    } else { /* cf->args->nelts == 3 */

        if (ngx_strcmp(value[1].data, "modified") != 0) {
            return "invalid value";
        }

        hcf->expires = NGX_HTTP_EXPIRES_MODIFIED;

        n = 2;
    }

    if (value[n].data[0] == '@') {
        value[n].data++;
        value[n].len--;
        minus = 0;

        if (hcf->expires == NGX_HTTP_EXPIRES_MODIFIED) {
            return "daily time cannot be used with \"modified\" parameter";
        }

        hcf->expires = NGX_HTTP_EXPIRES_DAILY;

    } else if (value[n].data[0] == '+') {
        value[n].data++;
        value[n].len--;
        minus = 0;

    } else if (value[n].data[0] == '-') {
        value[n].data++;
        value[n].len--;
        minus = 1;

    } else {
        minus = 0;
    }

    hcf->expires_time = ngx_parse_time(&value[n], 1);

    if (hcf->expires_time == (time_t) NGX_ERROR) {
        return "invalid value";
    }

    if (hcf->expires == NGX_HTTP_EXPIRES_DAILY
        && hcf->expires_time > 24 * 60 * 60)
    {
        return "daily time value must be less than 24 hours";
    }

    if (minus) {
        hcf->expires_time = - hcf->expires_time;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_headers_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_headers_conf_t *hcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_header_val_t             *hv;
    ngx_http_set_header_t             *set;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (hcf->headers == NULL) {
        hcf->headers = ngx_array_create(cf->pool, 1,
                                        sizeof(ngx_http_header_val_t));
        if (hcf->headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    hv = ngx_array_push(hcf->headers);
    if (hv == NULL) {
        return NGX_CONF_ERROR;
    }

    hv->hash = 1;
    hv->key = value[1];
    hv->handler = ngx_http_add_header;
    hv->offset = 0;

	//	遍历"ngx_http_set_headers"表中是否有与指令"add_header"设定的相同， 如果相同则将使用
	//	"ngx_http_set_headers"表中设置的handler和offest
    set = ngx_http_set_headers;
    for (i = 0; set[i].name.len; i++) {
        if (ngx_strcasecmp(value[1].data, set[i].name.data) != 0) {		//	不相等
            continue;
        }

        hv->offset = set[i].offset;
        hv->handler = set[i].handler;

        break;
    }

    if (value[2].len == 0) {
        ngx_memzero(&hv->value, sizeof(ngx_http_complex_value_t));
        return NGX_CONF_OK;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &hv->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
