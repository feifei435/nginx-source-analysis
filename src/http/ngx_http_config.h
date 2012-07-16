
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
#define _NGX_HTTP_CONFIG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* 
 *	[analy]	用来保存http各个模块使用的配置结构体地址 
 */
typedef struct {
    void        **main_conf;			//	用来保存ngx_http_module_t中create_main_conf回调函数返回的各个模块配置结构体的指针
    void        **srv_conf;				//  作用同上，但是create_srv_conf返回的指针
    void        **loc_conf;				//  作用同上，但是create_loc_conf返回的指针
} ngx_http_conf_ctx_t;


typedef struct {
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);						//	在读入配置前调用			
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);						//	在读入配置后调用

    void       *(*create_main_conf)(ngx_conf_t *cf);						//	创建main配置时调用
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);				//	在初始化main配置时调用（比如，把原来的默认值用nginx.conf读到的值来覆盖）

    void       *(*create_srv_conf)(ngx_conf_t *cf);							//	创建server配置时调用
    char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);	//	合并server和main配置时调用

    void       *(*create_loc_conf)(ngx_conf_t *cf);							//	创建location配置时调用
    char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);	//	合并location和server配置时调用
} ngx_http_module_t;


#define NGX_HTTP_MODULE           0x50545448   /* "HTTP" */

#define NGX_HTTP_MAIN_CONF        0x02000000		/* [analy]	指令使用区域为http-block内 */			
#define NGX_HTTP_SRV_CONF         0x04000000		/* [analy]	指令使用区域为http->server-block内 */
#define NGX_HTTP_LOC_CONF         0x08000000		/* [analy]	指令使用区域为http->server->location-block内 */
#define NGX_HTTP_UPS_CONF         0x10000000		/* [analy]	指令使用区域为upstream-block内 */
#define NGX_HTTP_SIF_CONF         0x20000000
#define NGX_HTTP_LIF_CONF         0x40000000
#define NGX_HTTP_LMT_CONF         0x80000000


#define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
#define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)



/* 
 *	[analy]	在request中获取ctx
 */
#define ngx_http_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define ngx_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define ngx_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]


/* 
 *	[analy]	在cf(ngx_conf_t) 中获取ctx
 */
#define ngx_http_conf_get_module_main_conf(cf, module)                        \
    ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_http_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_http_conf_get_module_loc_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]

/* 
 *	[analy]	在cycle中获取ctx
 */
#define ngx_http_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_http_module.index] ?                                 \
        ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NGX_HTTP_CONFIG_H_INCLUDED_ */
