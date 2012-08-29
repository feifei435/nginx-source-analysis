
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    struct sockaddr                *sockaddr;					//	指向 ngx_http_upstream_server_t --> addrs.sockaddr
    socklen_t                       socklen;					//	指向 ngx_http_upstream_server_t --> addrs.socklen
    ngx_str_t                       name;						//	指向 ngx_http_upstream_server_t --> addrs.name

//	当前权重和设定权重
    ngx_int_t                       current_weight;				//	指向字段 weight
    ngx_int_t                       weight;						//	将根据ngx_http_upstream_server_t的down值决定为0还是取ngx_http_upstream_server_t --> weight的值

//	失败次数和访问时间
    ngx_uint_t                      fails;
    time_t                          accessed;
    time_t                          checked;

    ngx_uint_t                      max_fails;					//	指向 ngx_http_upstream_server_t --> max_fails
    time_t                          fail_timeout;				//	指向 ngx_http_upstream_server_t --> fail_timeout

//	服务器是否参与策略  
    ngx_uint_t                      down;						//	指向 ngx_http_upstream_server_t --> down		/* unsigned  down:1; */

#if (NGX_HTTP_SSL)
    ngx_ssl_session_t              *ssl_session;   /* local to a process */
#endif
} ngx_http_upstream_rr_peer_t;


typedef struct ngx_http_upstream_rr_peers_s  ngx_http_upstream_rr_peers_t;

struct ngx_http_upstream_rr_peers_s {
    ngx_uint_t                      single;					//	是否只有单个服务器	/* unsigned  single:1; */
    ngx_uint_t                      number;					//	所管理的后端服务器个数（多个IP的服务器将会被解析成多个 ngx_http_upstream_rr_peer_t ）
    ngx_uint_t                      last_cached;

 /* ngx_mutex_t                    *mutex; */
    ngx_connection_t              **cached;

    ngx_str_t                      *name;			//	指向 ngx_http_upstream_srv_conf_t 中的 host 字段，在函数ngx_http_upstream_init_round_robin()中有设置

    ngx_http_upstream_rr_peers_t   *next;

    ngx_http_upstream_rr_peer_t     peer[1];
};


typedef struct {
    ngx_http_upstream_rr_peers_t   *peers;
    ngx_uint_t                      current;
    uintptr_t                      *tried;
    uintptr_t                       data;
} ngx_http_upstream_rr_peer_data_t;


ngx_int_t ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur);
ngx_int_t ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

#if (NGX_HTTP_SSL)
ngx_int_t
    ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
#endif


#endif /* _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
