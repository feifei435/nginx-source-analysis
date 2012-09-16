
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_OPEN_FILE_CACHE_H_INCLUDED_
#define _NGX_OPEN_FILE_CACHE_H_INCLUDED_


#define NGX_OPEN_FILE_DIRECTIO_OFF  NGX_MAX_OFF_T_VALUE

//	���ڱ�����ļ�����Ϣ
typedef struct {
    ngx_fd_t                 fd;					//	�ļ�������������򿪵���Ŀ¼���ߵ�����stat����ʧ�ܶ�������Ϊ NGX_INVALID_FILE��
    ngx_file_uniq_t          uniq;					//	i�ڵ���
    time_t                   mtime;					//	����޸�ʱ��
    off_t                    size;					//	�ļ���С
    off_t                    fs_size;				//	ռ���ļ�ϵͳ�Ĵ�С
    off_t                    directio;				//	��Ӧ "directio" ָ�����õĴ�С
    size_t                   read_ahead;			//	��Ӧ "read_ahead" ָ�����õĴ�С

    ngx_err_t                err;					//	errno(ģ����open��stat�ļ�ʱ�Ĵ�����)
    char                    *failed;				//	ʧ��ԭ��

    time_t                   valid;					//	ָ���˶೤ʱ����Ҫ���cache�еĻ�����Ŀ����Ч��Ϣ��Ĭ����60s����Ӧָ�� "open_file_cache_valid" ָ����ʱ��

    ngx_uint_t               min_uses;				//	ָ��cache��Сʹ�õĴ�����Ĭ����1�Σ���Ӧָ�� "open_file_cache_min_uses" ����
	
#if (NGX_HAVE_OPENAT)
    size_t                   disable_symlinks_from;
    unsigned                 disable_symlinks:2;
#endif

    unsigned                 test_dir:1;
    unsigned                 test_only:1;
    unsigned                 log:1;					//	�Ƿ�Ϊlog�ļ�������
    unsigned                 errors:1;				//	ָ���Ƿ�������һ���ļ�ʱ��¼cache����Ĭ���ǹر�״̬����Ӧָ�� "open_file_cache_errors" ����
    unsigned                 events:1;

    unsigned                 is_dir:1;				//	�Ƿ�ΪĿ¼
    unsigned                 is_file:1;				//	�Ƿ�Ϊ�ļ�
    unsigned                 is_link:1;				//	�Ƿ�Ϊ����
    unsigned                 is_exec:1;				//	�Ƿ��ִ��
    unsigned                 is_directio:1;
} ngx_open_file_info_t;


typedef struct ngx_cached_open_file_s  ngx_cached_open_file_t;

//	�뵥���ļ��������
struct ngx_cached_open_file_s {
    ngx_rbtree_node_t        node;
    ngx_queue_t              queue;

    u_char                  *name;							//	�������ļ�������(ngx_open_cached_file()����������)
    time_t                   created;						//	��������µ�ʱ��
    time_t                   accessed;						//	���ʵ�ʱ��

    ngx_fd_t                 fd;							//	�ļ�������fd
    ngx_file_uniq_t          uniq;							//	i�ڵ���
    time_t                   mtime;							//	����޸�ʱ��
    off_t                    size;							//	�ļ���С
    ngx_err_t                err;							//	errno(��open()��stat()ʧ�ܵ����ʱ�����ô�����)

    uint32_t                 uses;							//	�����ʹ�ô���

#if (NGX_HAVE_OPENAT)
    size_t                   disable_symlinks_from;				
    unsigned                 disable_symlinks:2;				
#endif

    unsigned                 count:24;						//	�ļ������ü�������ʾ�����ļ�����������ʹ����
    unsigned                 close:1;						//	��ʾ�ļ��Ƿ���Ҫ���ر�
    unsigned                 use_event:1;

    unsigned                 is_dir:1;						//	�Ƿ�ΪĿ¼
    unsigned                 is_file:1;						//	�Ƿ�Ϊ�ļ�
    unsigned                 is_link:1;						//	�Ƿ�Ϊ����
    unsigned                 is_exec:1;						//	�Ƿ��ִ��
    unsigned                 is_directio:1;

    ngx_event_t             *event;
};

//	�ļ�������������л����ļ��Ľṹ
typedef struct {
    ngx_rbtree_t             rbtree;
    ngx_rbtree_node_t        sentinel;
    ngx_queue_t              expire_queue;

    ngx_uint_t               current;				//	��ǰcache���ļ���������ʼֵΪ0
    ngx_uint_t               max;					//	ָ�� "open_file_cache"��max����ָ����cache�ļ����� (ngx_open_file_cache_init()����������)
    time_t                   inactive;				//	ָ�� "open_file_cache"��inactive����ָ����ʱ�� (ngx_open_file_cache_init()����������)
} ngx_open_file_cache_t;


typedef struct {
    ngx_open_file_cache_t   *cache;					//	ʹ�õ�cache
    ngx_cached_open_file_t  *file;					//	��Ӧ��cache�ļ�
    ngx_uint_t               min_uses;				//	������־��Сʹ�ô���
    ngx_log_t               *log;					//	ʹ�õ���־ָ��
} ngx_open_file_cache_cleanup_t;


typedef struct {

    /* ngx_connection_t stub to allow use c->fd as event ident */
    void                    *data;
    ngx_event_t             *read;
    ngx_event_t             *write;
    ngx_fd_t                 fd;

    ngx_cached_open_file_t  *file;
    ngx_open_file_cache_t   *cache;
} ngx_open_file_cache_event_t;


ngx_open_file_cache_t *ngx_open_file_cache_init(ngx_pool_t *pool,
    ngx_uint_t max, time_t inactive);
ngx_int_t ngx_open_cached_file(ngx_open_file_cache_t *cache, ngx_str_t *name,
    ngx_open_file_info_t *of, ngx_pool_t *pool);


#endif /* _NGX_OPEN_FILE_CACHE_H_INCLUDED_ */
