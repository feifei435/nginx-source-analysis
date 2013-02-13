
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CACHE_H_INCLUDED_
#define _NGX_HTTP_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_CACHE_MISS          1				//	����δ����
#define NGX_HTTP_CACHE_BYPASS        2
#define NGX_HTTP_CACHE_EXPIRED       3
#define NGX_HTTP_CACHE_STALE         4
#define NGX_HTTP_CACHE_UPDATING      5
#define NGX_HTTP_CACHE_HIT           6				//	��������
#define NGX_HTTP_CACHE_SCARCE        7

#define NGX_HTTP_CACHE_KEY_LEN       16


typedef struct {
    ngx_uint_t                       status;
    time_t                           valid;
} ngx_http_cache_valid_t;


typedef struct {
    ngx_rbtree_node_t                node;
    ngx_queue_t                      queue;

    u_char                           key[NGX_HTTP_CACHE_KEY_LEN
                                         - sizeof(ngx_rbtree_key_t)];

    unsigned                         count:20;					//	���ü�����������������
    unsigned                         uses:10;					//	�����ļ�������������ʹ��
    unsigned                         valid_msec:10;
    unsigned                         error:10;
    unsigned                         exists:1;					//	���ڶ�Ӧ��cache�ļ���ngx_http_file_cache_add()����
    unsigned                         updating:1;
    unsigned                         deleting:1;
                                     /* 11 unused bits */

    ngx_file_uniq_t                  uniq;
    time_t                           expire;					//	�����ļ���ʧЧʱ��
    time_t                           valid_sec;
    size_t                           body_start;
    off_t                            fs_size;
} ngx_http_file_cache_node_t;


struct ngx_http_cache_s {
    ngx_file_t                       file;								//	???
    ngx_array_t                      keys;
    uint32_t                         crc32;
    u_char                           key[NGX_HTTP_CACHE_KEY_LEN];		//	???

    ngx_file_uniq_t                  uniq;
    time_t                           valid_sec;
    time_t                           last_modified;
    time_t                           date;

    size_t                           header_start;
    size_t                           body_start;				//	u->conf->buffer_size; ���պ�˷������������ݻ������Ĵ�С
    off_t                            length;					//	????
    off_t                            fs_size;					//	???/

    ngx_uint_t                       min_uses;					//	u->conf->cache_min_uses, proxyģ��ʹ��ָ�� "proxy_cache_min_uses" ָ��
    ngx_uint_t                       error;
    ngx_uint_t                       valid_msec;

    ngx_buf_t                       *buf;

    ngx_http_file_cache_t           *file_cache;
    ngx_http_file_cache_node_t      *node;						//	���������ã���

    ngx_msec_t                       lock_timeout;				//	u->conf->cache_lock_timeout, proxyģ��ʹ��ָ�� "proxy_cache_lock_timeout" ָ��
    ngx_msec_t                       wait_time;

    ngx_event_t                      wait_event;

    unsigned                         lock:1;					//	u->conf->cache_lock, proxyģ��ʹ��ָ�� "proxy_cache_lock" ָ��
    unsigned                         waiting:1;

    unsigned                         updated:1;					//	???
    unsigned                         updating:1;
    unsigned                         exists:1;
    unsigned                         temp_file:1;
};


typedef struct {
    time_t                           valid_sec;
    time_t                           last_modified;
    time_t                           date;
    uint32_t                         crc32;
    u_short                          valid_msec;
    u_short                          header_start;
    u_short                          body_start;
} ngx_http_file_cache_header_t;


typedef struct {
    ngx_rbtree_t                     rbtree;
    ngx_rbtree_node_t                sentinel;
    ngx_queue_t                      queue;
    ngx_atomic_t                     cold;
    ngx_atomic_t                     loading;
    off_t                            size;
} ngx_http_file_cache_sh_t;


struct ngx_http_file_cache_s {
    ngx_http_file_cache_sh_t        *sh;							//	�ں��� ngx_http_file_cache_init����������
    ngx_slab_pool_t                 *shpool;						//	�ں��� ngx_http_file_cache_init����������

    ngx_path_t                      *path;							//	cache��·�����ں����� ngx_http_file_cache_set_slot��������

    off_t                            max_size;						//	cache���̵����ռ䣬�ں����� ngx_http_file_cache_set_slot��������
    size_t                           bsize;							//	ÿ������ֽ������ں��� ngx_http_file_cache_init����������

    time_t                           inactive;						//	����Ծʱ�䣬��ò�ʹ�þͱ�ɾ�����ں����� ngx_http_file_cache_set_slot��������

    ngx_uint_t                       files;							//	��ǰ�ж��ٸ�cache�ļ����ں��� ngx_http_file_cache_manage_fil()�����ã�
    ngx_uint_t                       loader_files;					//	Ĭ��100���ں����� ngx_http_file_cache_set_slot��������
    ngx_msec_t                       last;							//	���manage����loader���ʵ�ʱ�䣨�ں��� ngx_http_file_cache_manager()������ ��
    ngx_msec_t                       loader_sleep;					//	Ĭ��50���ں����� ngx_http_file_cache_set_slot�������� 
    ngx_msec_t                       loader_threshold;				//	Ĭ��200���ں����� ngx_http_file_cache_set_slot��������

    ngx_shm_zone_t                  *shm_zone;						//	�ں����� ngx_http_file_cache_set_slot��������
};


ngx_int_t ngx_http_file_cache_new(ngx_http_request_t *r);
ngx_int_t ngx_http_file_cache_create(ngx_http_request_t *r);
void ngx_http_file_cache_create_key(ngx_http_request_t *r);
ngx_int_t ngx_http_file_cache_open(ngx_http_request_t *r);
void ngx_http_file_cache_set_header(ngx_http_request_t *r, u_char *buf);
void ngx_http_file_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf);
ngx_int_t ngx_http_cache_send(ngx_http_request_t *);
void ngx_http_file_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf);
time_t ngx_http_file_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status);

char *ngx_http_file_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_file_cache_valid_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


extern ngx_str_t  ngx_http_cache_status[];


#endif /* _NGX_HTTP_CACHE_H_INCLUDED_ */
