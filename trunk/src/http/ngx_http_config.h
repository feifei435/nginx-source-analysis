
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
 *	[analy]	��������http����ģ��ʹ�õ����ýṹ���ַ 
 */
typedef struct {
    void        **main_conf;			//	��������ngx_http_module_t��create_main_conf�ص��������صĸ���ģ�����ýṹ���ָ��
    void        **srv_conf;				//  ����ͬ�ϣ�����create_srv_conf���ص�ָ��
    void        **loc_conf;				//  ����ͬ�ϣ�����create_loc_conf���ص�ָ��
} ngx_http_conf_ctx_t;


typedef struct {
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);						//	�ڶ�������ǰ����			
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);						//	�ڶ������ú����

    void       *(*create_main_conf)(ngx_conf_t *cf);						//	����main����ʱ����
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);				//	�ڳ�ʼ��main����ʱ���ã����磬��ԭ����Ĭ��ֵ��nginx.conf������ֵ�����ǣ�

    void       *(*create_srv_conf)(ngx_conf_t *cf);							//	����server����ʱ����
    char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);	//	�ϲ�server��main����ʱ����

    void       *(*create_loc_conf)(ngx_conf_t *cf);							//	����location����ʱ����
    char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);	//	�ϲ�location��server����ʱ����
} ngx_http_module_t;


#define NGX_HTTP_MODULE           0x50545448   /* "HTTP" */

#define NGX_HTTP_MAIN_CONF        0x02000000		/* [analy]	ָ��ʹ������Ϊhttp-block�� */			
#define NGX_HTTP_SRV_CONF         0x04000000		/* [analy]	ָ��ʹ������Ϊhttp->server-block�� */
#define NGX_HTTP_LOC_CONF         0x08000000		/* [analy]	ָ��ʹ������Ϊhttp->server->location-block�� */
#define NGX_HTTP_UPS_CONF         0x10000000		/* [analy]	ָ��ʹ������Ϊupstream-block�� */
#define NGX_HTTP_SIF_CONF         0x20000000
#define NGX_HTTP_LIF_CONF         0x40000000
#define NGX_HTTP_LMT_CONF         0x80000000


#define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
#define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)


#define ngx_http_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define ngx_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define ngx_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]


#define ngx_http_conf_get_module_main_conf(cf, module)                        \
    ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_http_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_http_conf_get_module_loc_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]

#define ngx_http_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_http_module.index] ?                                 \
        ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NGX_HTTP_CONFIG_H_INCLUDED_ */
