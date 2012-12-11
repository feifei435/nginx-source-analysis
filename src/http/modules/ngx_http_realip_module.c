
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 *	模块说明: 此模块默认是开启的， 通过--with-http_realip_module选项开启或关闭
 *				Q:	此模块在 NGX_HTTP_POST_READ_PHASE 和 NGX_HTTP_PREACCESS_PHASE阶段都设置了此handler, 为什么在preaccess阶段注册此模块？
 */


//	指令 "real_ip_header" 使用的类型
#define NGX_HTTP_REALIP_XREALIP  0				//	"X-Real-IP"				
#define NGX_HTTP_REALIP_XFWD     1				//	"X-Forwarded-For"
#define NGX_HTTP_REALIP_HEADER   2				//	

//	指令 "set_real_ip_from" 指定的IP地址和掩码
typedef struct {
    in_addr_t          mask;			
    in_addr_t          addr;
} ngx_http_realip_from_t;


typedef struct {
    ngx_array_t       *from;		//	指令 "set_real_ip_from" 使用时，将添加参数到此数组中	/* array of ngx_http_realip_from_t */
    ngx_uint_t         type;		//	指令 "real_ip_header" 使用的类型, 默认"X-Real-IP"	
    ngx_uint_t         hash;		//	指令 "real_ip_header" 指定的参数值的HASH
    ngx_str_t          header;		//	指令 "real_ip_header" 指定的参数值
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_uint_t         unixsock; /* unsigned  unixsock:2; */
#endif
} ngx_http_realip_loc_conf_t;


typedef struct {
    ngx_connection_t  *connection;
    struct sockaddr   *sockaddr;
    socklen_t          socklen;
    ngx_str_t          addr_text;
} ngx_http_realip_ctx_t;


static ngx_int_t ngx_http_realip_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_realip_set_addr(ngx_http_request_t *r, u_char *ip,
    size_t len);
static void ngx_http_realip_cleanup(void *data);
static char *ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_realip_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_realip_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_realip_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_realip_commands[] = {

	/*
	 *	语法：set_real_ip_from [the address|CIDR|”unix:”]
	 *	默认值：none
	 *		set_real_ip_from   192.168.1.0/24;
	 *		set_real_ip_from   192.168.2.1;
	 *	这个指令指定信任的代理IP，它们将会以精确的替换IP转发
	 */
    { ngx_string("set_real_ip_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_realip_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

	/*	设置需要使用哪个头来确定替换的IP地址[X-Real-IP|X-Forwarded-For]
	 *	默认: X-Real-IP 
	 */
    { ngx_string("real_ip_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_realip,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_realip_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_realip_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_realip_create_loc_conf,       /* create location configuration */
    ngx_http_realip_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_realip_module = {
    NGX_MODULE_V1,
    &ngx_http_realip_module_ctx,           /* module context */
    ngx_http_realip_commands,              /* module directives */
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

/*
	

*/
static ngx_int_t
ngx_http_realip_handler(ngx_http_request_t *r)
{
    u_char                      *ip, *p;
    size_t                       len;
    ngx_uint_t                   i, hash;
    ngx_list_part_t             *part;
    ngx_table_elt_t             *header;
    struct sockaddr_in          *sin;
    ngx_connection_t            *c;
    ngx_http_realip_ctx_t       *ctx;
    ngx_http_realip_from_t      *from;
    ngx_http_realip_loc_conf_t  *rlcf;


	//	获取realip模块在当前request的ctx值， 如果已经存在ctx则执行下一个模块
	//	当期请求如果已经检查到有"X-Forwarded-For"和"X_REAL_IP"等请求头，并且设置了客户端的真实IP
	//	后将不在执行此模块，非当前请求将继续检查此模块
    ctx = ngx_http_get_module_ctx(r, ngx_http_realip_module);

    if (ctx) {						//	执行当前phase的下一个handler
        return NGX_DECLINED;
    }

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_realip_module);

    if (rlcf->from == NULL			//	当未使用指令"set_real_ip_from"时，将直接运行本phase的下一个handler
#if (NGX_HAVE_UNIX_DOMAIN)
        && !rlcf->unixsock
#endif
       )
    {
        return NGX_DECLINED;
    }

    switch (rlcf->type) {

    case NGX_HTTP_REALIP_XREALIP:			//	默认类型

        if (r->headers_in.x_real_ip == NULL) {			//	请求头中没有 "X_REAL_IP" 
            return NGX_DECLINED;
        }

        len = r->headers_in.x_real_ip->value.len;
        ip = r->headers_in.x_real_ip->value.data;

        break;

    case NGX_HTTP_REALIP_XFWD:				//	"X-Forwarded-For"

        if (r->headers_in.x_forwarded_for == NULL) {	//	请求头中没有 "X-Forwarded-For"
            return NGX_DECLINED;
        }

        len = r->headers_in.x_forwarded_for->value.len;
        ip = r->headers_in.x_forwarded_for->value.data;


		//	????????
        for (p = ip + len - 1; p > ip; p--) {
            if (*p == ' ' || *p == ',') {
                p++;
                len -= p - ip;
                ip = p;
                break;
            }
        }

        break;

    default: /* NGX_HTTP_REALIP_HEADER */

        part = &r->headers_in.headers.part;
        header = part->elts;

        hash = rlcf->hash;
        len = rlcf->header.len;
        p = rlcf->header.data;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (hash == header[i].hash
                && len == header[i].key.len
                && ngx_strncmp(p, header[i].lowcase_key, len) == 0)
            {
                len = header[i].value.len;
                ip = header[i].value.data;

                goto found;
            }
        }

        return NGX_DECLINED;
    }

found:

    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "realip: \"%s\"", ip);

    /* AF_INET only */

    if (c->sockaddr->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) c->sockaddr;

        from = rlcf->from->elts;							//	遍历
        for (i = 0; i < rlcf->from->nelts; i++) {

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "realip: %08XD %08XD %08XD",
                           sin->sin_addr.s_addr, from[i].mask, from[i].addr);

            if ((sin->sin_addr.s_addr & from[i].mask) == from[i].addr) {
                return ngx_http_realip_set_addr(r, ip, len);
            }
        }
    }

#if (NGX_HAVE_UNIX_DOMAIN)

    if (c->sockaddr->sa_family == AF_UNIX && rlcf->unixsock) {
        return ngx_http_realip_set_addr(r, ip, len);
    }

#endif

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_realip_set_addr(ngx_http_request_t *r, u_char *ip, size_t len)
{
    u_char                 *p;
    ngx_int_t               rc;
    ngx_addr_t              addr;
    ngx_connection_t       *c;
    ngx_pool_cleanup_t     *cln;
    ngx_http_realip_ctx_t  *ctx;

	//	在请求的连接池上增加一个， 清理函数。（此清理函数什么时候被调用呢？ -- 在销毁内存池的时候会调用ngx_destroy_pool()）
    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_realip_ctx_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = cln->data;	//	ctx结构在 ngx_pool_cleanup_add（）函数中已经申请，此时直接使用即可
    ngx_http_set_ctx(r, ctx, ngx_http_realip_module);			//	设置realip模块的的ctx到当前请求的ctx中

    c = r->connection;

    rc = ngx_parse_addr(c->pool, &addr, ip, len);

    switch (rc) {
    case NGX_DECLINED:
        return NGX_DECLINED;
    case NGX_ERROR:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    default: /* NGX_OK */
        break;
    }

    p = ngx_pnalloc(c->pool, len);			//	为什么在connection的连接池上申请？？？
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(p, ip, len);

    cln->handler = ngx_http_realip_cleanup;

    ctx->connection = c;					//	设置正在使用的connection
    ctx->sockaddr = c->sockaddr;			//	备份与服务器连接的客户端socket信息
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;			//	备份与服务器连接的客户端的IP地址（ASCII格式)

	//	设置解析出的真实客户端IP信息
    c->sockaddr = addr.sockaddr;
    c->socklen = addr.socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return NGX_DECLINED;
}


static void
ngx_http_realip_cleanup(void *data)
{
    ngx_http_realip_ctx_t *ctx = data;

    ngx_connection_t  *c;

    c = ctx->connection;

    c->sockaddr = ctx->sockaddr;
    c->socklen = ctx->socklen;
    c->addr_text = ctx->addr_text;
}


static char *
ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_realip_loc_conf_t *rlcf = conf;

    ngx_int_t                rc;
    ngx_str_t               *value;
    ngx_cidr_t               cidr;
    ngx_http_realip_from_t  *from;

    value = cf->args->elts;

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
         rlcf->unixsock = 1;
         return NGX_CONF_OK;
    }

#endif

    if (rlcf->from == NULL) {
        rlcf->from = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_http_realip_from_t));
        if (rlcf->from == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    from = ngx_array_push(rlcf->from);
    if (from == NULL) {
        return NGX_CONF_ERROR;
    }

    rc = ngx_ptocidr(&value[1], &cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (cidr.family != AF_INET) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"set_real_ip_from\" supports IPv4 only");
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", &value[1]);
    }

    from->mask = cidr.u.in.mask;
    from->addr = cidr.u.in.addr;

    return NGX_CONF_OK;
}


static char *
ngx_http_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_realip_loc_conf_t *rlcf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "X-Real-IP") == 0) {
        rlcf->type = NGX_HTTP_REALIP_XREALIP;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "X-Forwarded-For") == 0) {
        rlcf->type = NGX_HTTP_REALIP_XFWD;
        return NGX_CONF_OK;
    }

    rlcf->type = NGX_HTTP_REALIP_HEADER;
    rlcf->hash = ngx_hash_strlow(value[1].data, value[1].data, value[1].len);
    rlcf->header = value[1];

    return NGX_CONF_OK;
}


static void *
ngx_http_realip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_realip_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_realip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->from = NULL;
     *     conf->hash = 0;
     *     conf->header = { 0, NULL };
     */

    conf->type = NGX_CONF_UNSET_UINT;
#if (NGX_HAVE_UNIX_DOMAIN)
	conf->unixsock = 2;
#endif

    return conf;
}


static char *
ngx_http_realip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_realip_loc_conf_t  *prev = parent;
    ngx_http_realip_loc_conf_t  *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

#if (NGX_HAVE_UNIX_DOMAIN)
    if (conf->unixsock == 2) {
        conf->unixsock = (prev->unixsock == 2) ? 0 : prev->unixsock;
    }
#endif

    ngx_conf_merge_uint_value(conf->type, prev->type, NGX_HTTP_REALIP_XREALIP);

    if (conf->header.len == 0) {
        conf->hash = prev->hash;
        conf->header = prev->header;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_realip_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realip_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realip_handler;

    return NGX_OK;
}
