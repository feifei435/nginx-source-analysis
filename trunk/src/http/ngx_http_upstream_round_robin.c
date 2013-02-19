
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_upstream_cmp_servers(const void *one,
    const void *two);
static ngx_uint_t
ngx_http_upstream_get_peer(ngx_http_upstream_rr_peers_t *peers);

#if (NGX_HTTP_SSL)

static ngx_int_t ngx_http_upstream_empty_set_session(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_empty_save_session(ngx_peer_connection_t *pc,
    void *data);

#endif

/*
 *			初始化服务器负载均衡表
 *			参数2: us -> ngx_http_upstream_main_conf_t 的 upstreams数组中的元素
 */
ngx_int_t
ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_url_t                      u;
    ngx_uint_t                     i, j, n;
    ngx_http_upstream_server_t    *server;
    ngx_http_upstream_rr_peers_t  *peers, *backup;

	//	1. 设置负载均衡初始化函数
    us->peer.init = ngx_http_upstream_init_round_robin_peer;

	//	检查当前的upstream块中是否有 ngx_http_upstream_server_t
    if (us->servers) {		//	us->servers ==> array of ngx_http_upstream_server_t
        server = us->servers->elts;

        n = 0;

		//	遍历当前的upstream block {..} 中的server ，统计除backup服务器以外所有 server 使用的IP个数
        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
        }

        peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t)						//	这里仅申请n-1个ngx_http_upstream_rr_peer_t结构是因为ngx_http_upstream_rr_peers_t结构中已经包含此结构
                              + sizeof(ngx_http_upstream_rr_peer_t) * (n - 1));
        if (peers == NULL) {
            return NGX_ERROR;
        }

        peers->single = (n == 1);
        peers->number = n;						//	设置非backup的后端服务器个数
        peers->name = &us->host;

        n = 0;

		//	对每个服务器的server进行赋值，由于域名可能对应多个IP，每个IP对应一个server
        for (i = 0; i < us->servers->nelts; i++) {
            for (j = 0; j < server[i].naddrs; j++) {
                if (server[i].backup) {
                    continue;
                }

                peers->peer[n].sockaddr = server[i].addrs[j].sockaddr;		//	指向 ngx_http_upstream_server_t --> addrs.sockaddr				
                peers->peer[n].socklen = server[i].addrs[j].socklen;		//	指向 ngx_http_upstream_server_t --> addrs.socklen
                peers->peer[n].name = server[i].addrs[j].name;				//	指向 ngx_http_upstream_server_t --> addrs.name
                peers->peer[n].max_fails = server[i].max_fails;				//	指向 ngx_http_upstream_server_t --> max_fails
                peers->peer[n].fail_timeout = server[i].fail_timeout;		//	指向 ngx_http_upstream_server_t --> fail_timeout
                peers->peer[n].down = server[i].down;						//	指向 ngx_http_upstream_server_t --> down
                peers->peer[n].weight = server[i].down ? 0 : server[i].weight;	//	如果此主机指定了down，将为0。否则指向  ngx_http_upstream_server_t --> weight
                peers->peer[n].current_weight = peers->peer[n].weight;		//	指向 ngx_http_upstream_rr_peer_t  --> weight
                n++;
            }
        }

		//	保存负载均衡使用的管理结构地址
        us->peer.data = peers;

		//	权重大的值，排放在前边
        ngx_sort(&peers->peer[0], (size_t) n,
                 sizeof(ngx_http_upstream_rr_peer_t),
                 ngx_http_upstream_cmp_servers);			

        /* backup servers */

        n = 0;

		//	统计backup后端服务器个数
        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
        }

        if (n == 0) {				//	如果没有backup服务器将直接返回
            return NGX_OK;
        }

        backup = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t)
                              + sizeof(ngx_http_upstream_rr_peer_t) * (n - 1));
        if (backup == NULL) {
            return NGX_ERROR;
        }

        peers->single = 0;
        backup->single = 0;
        backup->number = n;				//	设置backup的后端服务器个数
        backup->name = &us->host;

        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            for (j = 0; j < server[i].naddrs; j++) {
                if (!server[i].backup) {
                    continue;
                }

                backup->peer[n].sockaddr = server[i].addrs[j].sockaddr;
                backup->peer[n].socklen = server[i].addrs[j].socklen;
                backup->peer[n].name = server[i].addrs[j].name;
                backup->peer[n].weight = server[i].weight;						//	这里与上边有区别？？？
                backup->peer[n].current_weight = server[i].weight;				//	这里与上边有区别？？？
                backup->peer[n].max_fails = server[i].max_fails;
                backup->peer[n].fail_timeout = server[i].fail_timeout;
                backup->peer[n].down = server[i].down;
                n++;
            }
        }

        peers->next = backup;				//	将backup服务器挂载到正常负载服务器后边

        ngx_sort(&backup->peer[0], (size_t) n,
                 sizeof(ngx_http_upstream_rr_peer_t),
                 ngx_http_upstream_cmp_servers);

        return NGX_OK;
    }	//	enf if


    /* an upstream implicitly defined by proxy_pass, etc. */

//#####################################		主要是处理proxy_pass指令的	#####################################
    if (us->port == 0 && us->default_port == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = us->host;
    u.port = (in_port_t) (us->port ? us->port : us->default_port);

	//	解析域名
    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NGX_ERROR;
    }

	//	域名对应的IP地址个数
    n = u.naddrs;

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t)
                              + sizeof(ngx_http_upstream_rr_peer_t) * (n - 1));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peers->single = (n == 1);				//	是否只有单个后端服务器（一个后端服务器可能对应多个IP）
    peers->number = n;
    peers->name = &us->host;

    for (i = 0; i < u.naddrs; i++) {
        peers->peer[i].sockaddr = u.addrs[i].sockaddr;
        peers->peer[i].socklen = u.addrs[i].socklen;
        peers->peer[i].name = u.addrs[i].name;
        peers->peer[i].weight = 1;
        peers->peer[i].current_weight = 1;
        peers->peer[i].max_fails = 1;
        peers->peer[i].fail_timeout = 10;
    }

    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return NGX_OK;
}

//	权重大的值，排放在前边
static ngx_int_t
ngx_http_upstream_cmp_servers(const void *one, const void *two)
{
    ngx_http_upstream_rr_peer_t  *first, *second;

    first = (ngx_http_upstream_rr_peer_t *) one;
    second = (ngx_http_upstream_rr_peer_t *) two;

    return (first->weight < second->weight);
}

/*  
 *	负载均衡rr的初始化
 */
ngx_int_t
ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                         n;
    ngx_http_upstream_rr_peer_data_t  *rrp;

    rrp = r->upstream->peer.data;

	//	设置负载均衡RR实用的数据结构
    if (rrp == NULL) {
        rrp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        r->upstream->peer.data = rrp;	//	设置 ngx_http_upstream_rr_peer_data_t
    }

    rrp->peers = us->peer.data;			//	获取后端服务器的管理表(负载均衡模块使用的管理表)
    rrp->current = 0;

    n = rrp->peers->number;				//	获取的后端服务器的正常列表个数

	//	当存在backup后端服务器列表时，如果backup后端服务器列表个数大于正常后端服务器个数，则取backup服务器的个数来用于申请尝试位图
    if (rrp->peers->next && rrp->peers->next->number > n) {
        n = rrp->peers->next->number;
    }

	/*	tried中记录了服务器当前是否被尝试连接过。他是一个位图。如果服务器数量小于32/64，
		则只需在一个int中即可记录下所有服务器状态。如果服务器数量大于32/64，则需在内存池中申请内存来存储 */

    if (n <= 8 * sizeof(uintptr_t)) {

        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (n + (8 * sizeof(uintptr_t) - 1)) / (8 * sizeof(uintptr_t));	//	计算用于保存服务器状态的空间

        rrp->tried = ngx_pcalloc(r->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }

    r->upstream->peer.get = ngx_http_upstream_get_round_robin_peer;
    r->upstream->peer.free = ngx_http_upstream_free_round_robin_peer;
    r->upstream->peer.tries = rrp->peers->number;									//	设置尝试连接的次数（等于后端正常服务器的个数）

#if (NGX_HTTP_SSL)
    r->upstream->peer.set_session =
                               ngx_http_upstream_set_round_robin_peer_session;
    r->upstream->peer.save_session =
                               ngx_http_upstream_save_round_robin_peer_session;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur)
{
    u_char                            *p;
    size_t                             len;
    ngx_uint_t                         i, n;
    struct sockaddr_in                *sin;
    ngx_http_upstream_rr_peers_t      *peers;
    ngx_http_upstream_rr_peer_data_t  *rrp;

    rrp = r->upstream->peer.data;

    if (rrp == NULL) {
        rrp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        r->upstream->peer.data = rrp;
    }

    peers = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_rr_peers_t)
                     + sizeof(ngx_http_upstream_rr_peer_t) * (ur->naddrs - 1));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peers->single = (ur->naddrs == 1);
    peers->number = ur->naddrs;
    peers->name = &ur->host;

    if (ur->sockaddr) {
        peers->peer[0].sockaddr = ur->sockaddr;
        peers->peer[0].socklen = ur->socklen;
        peers->peer[0].name = ur->host;
        peers->peer[0].weight = 1;
        peers->peer[0].current_weight = 1;
        peers->peer[0].max_fails = 1;
        peers->peer[0].fail_timeout = 10;

    } else {

        for (i = 0; i < ur->naddrs; i++) {

            len = NGX_INET_ADDRSTRLEN + sizeof(":65536") - 1;

            p = ngx_pnalloc(r->pool, len);
            if (p == NULL) {
                return NGX_ERROR;
            }

            len = ngx_inet_ntop(AF_INET, &ur->addrs[i], p, NGX_INET_ADDRSTRLEN);
            len = ngx_sprintf(&p[len], ":%d", ur->port) - p;

            sin = ngx_pcalloc(r->pool, sizeof(struct sockaddr_in));
            if (sin == NULL) {
                return NGX_ERROR;
            }

            sin->sin_family = AF_INET;
            sin->sin_port = htons(ur->port);
            sin->sin_addr.s_addr = ur->addrs[i];

            peers->peer[i].sockaddr = (struct sockaddr *) sin;
            peers->peer[i].socklen = sizeof(struct sockaddr_in);
            peers->peer[i].name.len = len;
            peers->peer[i].name.data = p;
            peers->peer[i].weight = 1;
            peers->peer[i].current_weight = 1;
            peers->peer[i].max_fails = 1;
            peers->peer[i].fail_timeout = 10;
        }
    }

    rrp->peers = peers;
    rrp->current = 0;

	//??????????
    if (rrp->peers->number <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        rrp->tried = ngx_pcalloc(r->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }

    r->upstream->peer.get = ngx_http_upstream_get_round_robin_peer;
    r->upstream->peer.free = ngx_http_upstream_free_round_robin_peer;
    r->upstream->peer.tries = rrp->peers->number;
#if (NGX_HTTP_SSL)
    r->upstream->peer.set_session = ngx_http_upstream_empty_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_empty_save_session;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;			//	在函数 ngx_http_upstream_init_round_robin_peer() 中设置

    time_t                         now;
    uintptr_t                      m;
    ngx_int_t                      rc;
    ngx_uint_t                     i, n;
    ngx_connection_t              *c;
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get rr peer, try: %ui", pc->tries);

    now = ngx_time();

    /* ngx_lock_mutex(rrp->peers->mutex); */

    if (rrp->peers->last_cached) {

        /* cached connection */

        c = rrp->peers->cached[rrp->peers->last_cached];
        rrp->peers->last_cached--;

        /* ngx_unlock_mutex(ppr->peers->mutex); */

#if (NGX_THREADS)
        c->read->lock = c->read->own_lock;
        c->write->lock = c->write->own_lock;
#endif

        pc->connection = c;
        pc->cached = 1;

        return NGX_OK;
    }

    pc->cached = 0;
    pc->connection = NULL;

	//	只有一个服务器，直接返回第0项
    if (rrp->peers->single) {
        peer = &rrp->peers->peer[0];

    } else {

        /* there are several peers */

        if (pc->tries == rrp->peers->number) {

            /* it's a first try - get a current peer */

            i = pc->tries;

            for ( ;; ) {

				//	获取权重最高的服务器
                rrp->current = ngx_http_upstream_get_peer(rrp->peers);

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                               "get rr peer, current: %ui %i",
                               rrp->current,
                               rrp->peers->peer[rrp->current].current_weight);

				//	计算当前获取的服务器在位图中的标记
                n = rrp->current / (8 * sizeof(uintptr_t));
                m = (uintptr_t) 1 << rrp->current % (8 * sizeof(uintptr_t));

                if (!(rrp->tried[n] & m)) {	//	未尝试过时， 获取服务器信息
                    peer = &rrp->peers->peer[rrp->current];

                    if (!peer->down) {

                        if (peer->max_fails == 0
                            || peer->fails < peer->max_fails)
                        {
                            break;
                        }

                        if (now - peer->checked > peer->fail_timeout) {
                            peer->checked = now;
                            break;
                        }

                        peer->current_weight = 0;

                    } else {
                        rrp->tried[n] |= m;
                    }

                    pc->tries--;
                }

                if (pc->tries == 0) {
                    goto failed;
                }

                if (--i == 0) {
                    ngx_log_error(NGX_LOG_ALERT, pc->log, 0,
                                  "round robin upstream stuck on %ui tries",
                                  pc->tries);
                    goto failed;
                }
            }		//	end for

            peer->current_weight--;

        } else {

			//	已经不是第一次尝试连接后端服务器时

            i = pc->tries;

            for ( ;; ) {
                n = rrp->current / (8 * sizeof(uintptr_t));
                m = (uintptr_t) 1 << rrp->current % (8 * sizeof(uintptr_t));

                if (!(rrp->tried[n] & m)) {

                    peer = &rrp->peers->peer[rrp->current];

                    if (!peer->down) {

                        if (peer->max_fails == 0
                            || peer->fails < peer->max_fails)
                        {
                            break;
                        }

                        if (now - peer->checked > peer->fail_timeout) {
                            peer->checked = now;
                            break;
                        }

                        peer->current_weight = 0;

                    } else {
                        rrp->tried[n] |= m;
                    }

                    pc->tries--;
                }

                rrp->current++;

                if (rrp->current >= rrp->peers->number) {
                    rrp->current = 0;
                }

                if (pc->tries == 0) {
                    goto failed;
                }

                if (--i == 0) {
                    ngx_log_error(NGX_LOG_ALERT, pc->log, 0,
                                  "round robin upstream stuck on %ui tries",
                                  pc->tries);
                    goto failed;
                }
            }

            peer->current_weight--;
        }

        rrp->tried[n] |= m;
    }

	//	确定后端服务器的IP和端口信息，设置 ngx_peer_connection_t
    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    /* ngx_unlock_mutex(rrp->peers->mutex); */

    if (pc->tries == 1 && rrp->peers->next) {
        pc->tries += rrp->peers->next->number;

        n = rrp->peers->next->number / (8 * sizeof(uintptr_t)) + 1;
        for (i = 0; i < n; i++) {
             rrp->tried[i] = 0;
        }
    }

    return NGX_OK;

failed:

    peers = rrp->peers;

	//	有backup服务器
    if (peers->next) {

        /* ngx_unlock_mutex(peers->mutex); */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "backup servers");

        rrp->peers = peers->next;
        pc->tries = rrp->peers->number;

		//	reset bitmap variable
        n = rrp->peers->number / (8 * sizeof(uintptr_t)) + 1;
        for (i = 0; i < n; i++) {
             rrp->tried[i] = 0;
        }

		//	再次获取一个服务器
        rc = ngx_http_upstream_get_round_robin_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        /* ngx_lock_mutex(peers->mutex); */
    }

    /* all peers failed, mark them as live for quick recovery */

//	################	所有服务器已经无效	 ################
    for (i = 0; i < peers->number; i++) {
        peers->peer[i].fails = 0;
    }

    /* ngx_unlock_mutex(peers->mutex); */

    pc->name = peers->name;

    return NGX_BUSY;
}

/*
 *	从所有的服务器中选出权值最高的服务器。如果所有server当前权重都为0，那么将所有server的当前权重恢复到设定权重值。
 */
static ngx_uint_t
ngx_http_upstream_get_peer(ngx_http_upstream_rr_peers_t *peers)
{
    ngx_uint_t                    i, n, reset = 0;
    ngx_http_upstream_rr_peer_t  *peer;

    peer = &peers->peer[0];

    for ( ;; ) {

        for (i = 0; i < peers->number; i++) {

            if (peer[i].current_weight <= 0) {
                continue;
            }

			//	1. 找到权重大于0的服务器
            n = i;

            while (i < peers->number - 1) {			//	非最后一个服务器，进入循环

                i++;

                if (peer[i].current_weight <= 0) {
                    continue;
                }

                if (peer[n].current_weight * 1000 / peer[i].current_weight
                    > peer[n].weight * 1000 / peer[i].weight)
                {
                    return n;
                }

                n = i;
            }

            if (peer[i].current_weight > 0) {
                n = i;
            }

            return n;
        }

		//	是否已经reset权重，如果已经reset，将直接返回0
        if (reset++) {
            return 0;
        }

		//	重新设置初始权重
        for (i = 0; i < peers->number; i++) {
            peer[i].current_weight = peer[i].weight;
        }
    }
}


void
ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    time_t                       now;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free rr peer %ui %ui", pc->tries, state);

    if (state == 0 && pc->tries == 0) {
        return;
    }

    /* TODO: NGX_PEER_KEEPALIVE */

    if (rrp->peers->single) {
        pc->tries = 0;
        return;
    }

    peer = &rrp->peers->peer[rrp->current];

    if (state & NGX_PEER_FAILED) {
        now = ngx_time();

        /* ngx_lock_mutex(rrp->peers->mutex); */

        peer->fails++;
        peer->accessed = now;
        peer->checked = now;

        if (peer->max_fails) {
            peer->current_weight -= peer->weight / peer->max_fails;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "free rr peer failed: %ui %i",
                       rrp->current, peer->current_weight);

        if (peer->current_weight < 0) {
            peer->current_weight = 0;
        }

        /* ngx_unlock_mutex(rrp->peers->mutex); */

    } else {

        /* mark peer live if check passed */

        if (peer->accessed < peer->checked) {
            peer->fails = 0;
        }
    }

    rrp->current++;

    if (rrp->current >= rrp->peers->number) {
        rrp->current = 0;
    }

    if (pc->tries) {
        pc->tries--;
    }

    /* ngx_unlock_mutex(rrp->peers->mutex); */
}


#if (NGX_HTTP_SSL)

ngx_int_t
ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                     rc;
    ngx_ssl_session_t            *ssl_session;
    ngx_http_upstream_rr_peer_t  *peer;

    peer = &rrp->peers->peer[rrp->current];

    /* TODO: threads only mutex */
    /* ngx_lock_mutex(rrp->peers->mutex); */

    ssl_session = peer->ssl_session;

    rc = ngx_ssl_set_session(pc->connection, ssl_session);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "set session: %p:%d",
                   ssl_session, ssl_session ? ssl_session->references : 0);

    /* ngx_unlock_mutex(rrp->peers->mutex); */

    return rc;
}


void
ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    ngx_ssl_session_t            *old_ssl_session, *ssl_session;
    ngx_http_upstream_rr_peer_t  *peer;

    ssl_session = ngx_ssl_get_session(pc->connection);

    if (ssl_session == NULL) {
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "save session: %p:%d", ssl_session, ssl_session->references);

    peer = &rrp->peers->peer[rrp->current];

    /* TODO: threads only mutex */
    /* ngx_lock_mutex(rrp->peers->mutex); */

    old_ssl_session = peer->ssl_session;
    peer->ssl_session = ssl_session;

    /* ngx_unlock_mutex(rrp->peers->mutex); */

    if (old_ssl_session) {

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "old session: %p:%d",
                       old_ssl_session, old_ssl_session->references);

        /* TODO: may block */

        ngx_ssl_free_session(old_ssl_session);
    }
}


static ngx_int_t
ngx_http_upstream_empty_set_session(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


static void
ngx_http_upstream_empty_save_session(ngx_peer_connection_t *pc, void *data)
{
    return;
}

#endif
