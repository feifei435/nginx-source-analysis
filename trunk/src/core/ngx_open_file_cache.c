
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 * open file cache caches
 *    open file handles with stat() info;
 *    directories stat() info;
 *    files and directories errors: not found, access denied, etc.
 */


#define NGX_MIN_READ_AHEAD  (128 * 1024)


static void ngx_open_file_cache_cleanup(void *data);
#if (NGX_HAVE_OPENAT)
static ngx_fd_t ngx_openat_file_owner(ngx_fd_t at_fd, const u_char *name,
    ngx_int_t mode, ngx_int_t create, ngx_int_t access, ngx_log_t *log);
#endif
static ngx_fd_t ngx_open_file_wrapper(ngx_str_t *name,
    ngx_open_file_info_t *of, ngx_int_t mode, ngx_int_t create,
    ngx_int_t access, ngx_log_t *log);
static ngx_int_t ngx_file_info_wrapper(ngx_str_t *name,
    ngx_open_file_info_t *of, ngx_file_info_t *fi, ngx_log_t *log);
static ngx_int_t ngx_open_and_stat_file(ngx_str_t *name,
    ngx_open_file_info_t *of, ngx_log_t *log);
static void ngx_open_file_add_event(ngx_open_file_cache_t *cache,
    ngx_cached_open_file_t *file, ngx_open_file_info_t *of, ngx_log_t *log);
static void ngx_open_file_cleanup(void *data);
static void ngx_close_cached_file(ngx_open_file_cache_t *cache,
    ngx_cached_open_file_t *file, ngx_uint_t min_uses, ngx_log_t *log);
static void ngx_open_file_del_event(ngx_cached_open_file_t *file);
static void ngx_expire_old_cached_files(ngx_open_file_cache_t *cache,
    ngx_uint_t n, ngx_log_t *log);
static void ngx_open_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_cached_open_file_t *
    ngx_open_file_lookup(ngx_open_file_cache_t *cache, ngx_str_t *name,
    uint32_t hash);
static void ngx_open_file_cache_remove(ngx_event_t *ev);


ngx_open_file_cache_t *
ngx_open_file_cache_init(ngx_pool_t *pool, ngx_uint_t max, time_t inactive)
{
    ngx_pool_cleanup_t     *cln;
    ngx_open_file_cache_t  *cache;

    cache = ngx_palloc(pool, sizeof(ngx_open_file_cache_t));
    if (cache == NULL) {
        return NULL;
    }

	//	�������ʼ��
    ngx_rbtree_init(&cache->rbtree, &cache->sentinel,
                    ngx_open_file_cache_rbtree_insert_value);

	//	���г�ʼ��
    ngx_queue_init(&cache->expire_queue);

    cache->current = 0;
    cache->max = max;
    cache->inactive = inactive;

	//	����һ���ڴ��������
    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_open_file_cache_cleanup;
    cln->data = cache;

    return cache;
}

/* 
 *	[analy]	��������cache�ļ�
 */
static void
ngx_open_file_cache_cleanup(void *data)
{
    ngx_open_file_cache_t  *cache = data;

    ngx_queue_t             *q;
    ngx_cached_open_file_t  *file;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "open file cache cleanup");

    for ( ;; ) {

		//	����Ϊ��ֱ�ӷ���
        if (ngx_queue_empty(&cache->expire_queue)) {
            break;
        }

		//	��ȡ�����е�β�ڵ㣬���һ���ڵ����ʱ��û��ʹ�õ�
        q = ngx_queue_last(&cache->expire_queue);							

		//	��ȡ�ýڵ㸽���Ļ����ļ��ṹ��ַ
        file = ngx_queue_data(q, ngx_cached_open_file_t, queue);			

		//	���ýڵ��ڶ�����ɾ��
        ngx_queue_remove(q);												

		//	�ں������ɾ����
        ngx_rbtree_delete(&cache->rbtree, &file->node);						

		//	���������һ
        cache->current--;													

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "delete cached open file: %s", file->name);

		//	�����ļ�û�д����������һ����ļ�����Ŀ¼��
		//	�رջ����ļ�(ǿ�����û����ļ���������ռ��)
        if (!file->err && !file->is_dir) {						
            file->close = 1;
            file->count = 0;												
            ngx_close_cached_file(cache, file, 0, ngx_cycle->log);

        } else {
			//	����Ŀ¼��ɾ�������cache�ļ��ṹ��cache�ļ�������ռ�õ��ڴ�
            ngx_free(file->name);
            ngx_free(file);
        }
    }

    if (cache->current) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "%d items still leave in open file cache",
                      cache->current);
    }

    if (cache->rbtree.root != cache->rbtree.sentinel) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "rbtree still is not empty in open file cache");

    }
}


ngx_int_t
ngx_open_cached_file(ngx_open_file_cache_t *cache, ngx_str_t *name,
    ngx_open_file_info_t *of, ngx_pool_t *pool)
{
    time_t                          now;
    uint32_t                        hash;
    ngx_int_t                       rc;
    ngx_file_info_t                 fi;
    ngx_pool_cleanup_t             *cln;
    ngx_cached_open_file_t         *file;
    ngx_pool_cleanup_file_t        *clnf;
    ngx_open_file_cache_cleanup_t  *ofcln;

    of->fd = NGX_INVALID_FILE;				//	�ļ���������ʼ��
    of->err = 0;							//	���������0


	//	ϵͳû�п������湦��
    if (cache == NULL) {

        if (of->test_only) {

            if (ngx_file_info_wrapper(name, of, &fi, pool->log)
                == NGX_FILE_ERROR)
            {
                return NGX_ERROR;
            }

            of->uniq = ngx_file_uniq(&fi);
            of->mtime = ngx_file_mtime(&fi);
            of->size = ngx_file_size(&fi);
            of->fs_size = ngx_file_fs_size(&fi);
            of->is_dir = ngx_is_dir(&fi);
            of->is_file = ngx_is_file(&fi);
            of->is_link = ngx_is_link(&fi);
            of->is_exec = ngx_is_exec(&fi);

            return NGX_OK;
        }

        cln = ngx_pool_cleanup_add(pool, sizeof(ngx_pool_cleanup_file_t));
        if (cln == NULL) {
            return NGX_ERROR;
        }

        rc = ngx_open_and_stat_file(name, of, pool->log);

        if (rc == NGX_OK && !of->is_dir) {
            cln->handler = ngx_pool_cleanup_file;
            clnf = cln->data;

            clnf->fd = of->fd;
            clnf->name = name->data;
            clnf->log = pool->log;
        }

        return rc;
    }

	//	ע��cleaup��������request��pool�ϣ�����������������±߸���������������������ʲôʱ��ִ�У�������������
    cln = ngx_pool_cleanup_add(pool, sizeof(ngx_open_file_cache_cleanup_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

	//	��ȡ��ǰʱ��
    now = ngx_time();

	//	�������ּ���CRC
    hash = ngx_crc32_long(name->data, name->len);

	//	�ھ�̬�ļ�������ϲ��Ҵ��ļ�
    file = ngx_open_file_lookup(cache, name, hash);

	//	��cache���ҵ��ļ�
    if (file) {

        file->uses++;							//	����cache�ļ���ʹ�ô�����һ

        ngx_queue_remove(&file->queue);			//	����cache�ļ���expire_queue������ɾ����Ϊʲôɾ������


		//	???????
        if (file->fd == NGX_INVALID_FILE && file->err == 0 && !file->is_dir) {

            /* file was not used often enough to keep open */

            rc = ngx_open_and_stat_file(name, of, pool->log);

            if (rc != NGX_OK && (of->err == 0 || !of->errors)) {
                goto failed;
            }

            goto add_event;
        }

        if (file->use_event
            || (file->event == NULL
                && (of->uniq == 0 || of->uniq == file->uniq)
                && now - file->created < of->valid
#if (NGX_HAVE_OPENAT)
                && of->disable_symlinks == file->disable_symlinks
                && of->disable_symlinks_from == file->disable_symlinks_from
#endif
            ))
        {
            if (file->err == 0) {

                of->fd = file->fd;
                of->uniq = file->uniq;
                of->mtime = file->mtime;
                of->size = file->size;

                of->is_dir = file->is_dir;
                of->is_file = file->is_file;
                of->is_link = file->is_link;
                of->is_exec = file->is_exec;
                of->is_directio = file->is_directio;

                if (!file->is_dir) {
                    file->count++;
                    ngx_open_file_add_event(cache, file, of, pool->log);
                }

            } else {
                of->err = file->err;
#if (NGX_HAVE_OPENAT)
                of->failed = file->disable_symlinks ? ngx_openat_file_n
                                                    : ngx_open_file_n;
#else
                of->failed = ngx_open_file_n;
#endif
            }

            goto found;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_CORE, pool->log, 0,
                       "retest open file: %s, fd:%d, c:%d, e:%d",
                       file->name, file->fd, file->count, file->err);

        if (file->is_dir) {

            /*
             * chances that directory became file are very small
             * so test_dir flag allows to use a single syscall
             * in ngx_file_info() instead of three syscalls
             */

            of->test_dir = 1;
        }

        of->fd = file->fd;
        of->uniq = file->uniq;

        rc = ngx_open_and_stat_file(name, of, pool->log);

        if (rc != NGX_OK && (of->err == 0 || !of->errors)) {
            goto failed;
        }

        if (of->is_dir) {

            if (file->is_dir || file->err) {
                goto update;
            }

            /* file became directory */

        } else if (of->err == 0) {  /* file */

            if (file->is_dir || file->err) {
                goto add_event;
            }

            if (of->uniq == file->uniq) {

                if (file->event) {
                    file->use_event = 1;
                }

                of->is_directio = file->is_directio;

                goto update;
            }

            /* file was changed */

        } else { /* error to cache */

            if (file->err || file->is_dir) {
                goto update;
            }

            /* file was removed, etc. */
        }

        if (file->count == 0) {

            ngx_open_file_del_event(file);

            if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
                              ngx_close_file_n " \"%V\" failed", name);
            }

            goto add_event;
        }

		//	�����ļ����ı䣬��Ҫ����cache�ļ����н���cache�ļ��ڵ�Ӻ������ɾ��
        ngx_rbtree_delete(&cache->rbtree, &file->node);					

        cache->current--;												

        file->close = 1;				//	Ϊʲô���⸳ֵ������

        goto create;					//	��������create��ԭ�����ϱ��Ѿ�����ngx_open_and_stat_file()������
    }

    /* not found */
	//	���û����cache���ҵ��������´��ļ�����ȡ�ļ���Ϣ
    rc = ngx_open_and_stat_file(name, of, pool->log);

    if (rc != NGX_OK && (of->err == 0 || !of->errors)) {
        goto failed;
    }

create:

	//	a. ��ǰ������ļ��������ڻ������ޣ���ǿ��expire����cache
    if (cache->current >= cache->max) {				//	open_file_cache�����ж�����Ǹ�maxָ��cache��������
        ngx_expire_old_cached_files(cache, 0, pool->log);
    }

	//	b. ����һ��cache�ļ��ṹ
    file = ngx_alloc(sizeof(ngx_cached_open_file_t), pool->log);

    if (file == NULL) {
        goto failed;
    }

	//	c. Ϊcache���ļ��ṹ��ֵ
    file->name = ngx_alloc(name->len + 1, pool->log);			//	e.g. name = "/usr/local/nginx/html/index.html"

    if (file->name == NULL) {
        ngx_free(file);
        file = NULL;
        goto failed;
    }

    ngx_cpystrn(file->name, name->data, name->len + 1);

    file->node.key = hash;										//	���û����ļ��ڵ��key

    ngx_rbtree_insert(&cache->rbtree, &file->node);				//	����ǰ�Ļ����ļ��ڵ��������

    cache->current++;											//	���ӻ���ĸ���

    file->uses = 1;												//	��д����ʹ�ô���
    file->count = 0;											//	�ļ�������ʹ�ô���
    file->use_event = 0;										//	
    file->event = NULL;

add_event:

    ngx_open_file_add_event(cache, file, of, pool->log);		//	���û��ʹ��kqueue���˺���������ִ��

update:

    file->fd = of->fd;					
    file->err = of->err;
#if (NGX_HAVE_OPENAT)
    file->disable_symlinks = of->disable_symlinks;
    file->disable_symlinks_from = of->disable_symlinks_from;
#endif

    if (of->err == 0) {											//	���û�д���������Ϊcache�ļ���ֵ
        file->uniq = of->uniq;
        file->mtime = of->mtime;
        file->size = of->size;

        file->close = 0;

        file->is_dir = of->is_dir;
        file->is_file = of->is_file;
        file->is_link = of->is_link;
        file->is_exec = of->is_exec;
        file->is_directio = of->is_directio;

        if (!of->is_dir) {										//	����Ŀ¼�������ļ����ü���
            file->count++;
        }
    }

    file->created = now;										//	���´���ʱ��

found:

    file->accessed = now;											//	���÷���ʱ��

    ngx_queue_insert_head(&cache->expire_queue, &file->queue);		//	��cache�ļ�������ڶ����е��ײ�(β�����ʱ��û��ʹ�õ�)

    ngx_log_debug5(NGX_LOG_DEBUG_CORE, pool->log, 0,
                   "cached open file: %s, fd:%d, c:%d, e:%d, u:%d",
                   file->name, file->fd, file->count, file->err, file->uses);

    if (of->err == 0) {				//	û�в���������������cache�ļ�����������Ȼ��ֱ�ӷ���

        if (!of->is_dir) {					
            cln->handler = ngx_open_file_cleanup;		//	ע����������ʲôʱ��ִ���أ�������������������
            ofcln = cln->data;							//	��ȡ�� ngx_pool_cleanup_add() ���������������cache�ṹָ��

            ofcln->cache = cache;						//	ʹ�õ�cache
            ofcln->file = file;							//	��Ӧ��cache�ļ�
            ofcln->min_uses = of->min_uses;				//	����cache��Сʹ�ô���
            ofcln->log = pool->log;						//	ʹ�õ���־
        }

        return NGX_OK;
    }

    return NGX_ERROR;

failed:

    if (file) {
        ngx_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        if (file->count == 0) {

            if (file->fd != NGX_INVALID_FILE) {
                if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
                                  ngx_close_file_n " \"%s\" failed",
                                  file->name);
                }
            }

            ngx_free(file->name);
            ngx_free(file);

        } else {
            file->close = 1;
        }
    }

    if (of->fd != NGX_INVALID_FILE) {
        if (ngx_close_file(of->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
                          ngx_close_file_n " \"%V\" failed", name);
        }
    }

    return NGX_ERROR;
}


#if (NGX_HAVE_OPENAT)

static ngx_fd_t
ngx_openat_file_owner(ngx_fd_t at_fd, const u_char *name,
    ngx_int_t mode, ngx_int_t create, ngx_int_t access, ngx_log_t *log)
{
    ngx_fd_t         fd;
    ngx_err_t        err;
    ngx_file_info_t  fi, atfi;

    /*
     * To allow symlinks with the same owner, use openat() (followed
     * by fstat()) and fstatat(AT_SYMLINK_NOFOLLOW), and then compare
     * uids between fstat() and fstatat().
     *
     * As there is a race between openat() and fstatat() we don't
     * know if openat() in fact opened symlink or not.  Therefore,
     * we have to compare uids even if fstatat() reports the opened
     * component isn't a symlink (as we don't know whether it was
     * symlink during openat() or not).
     */

    fd = ngx_openat_file(at_fd, name, mode, create, access);

    if (fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }

    if (ngx_file_at_info(at_fd, name, &atfi, AT_SYMLINK_NOFOLLOW)
        == NGX_FILE_ERROR)
    {
        err = ngx_errno;
        goto failed;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        err = ngx_errno;
        goto failed;
    }

    if (fi.st_uid != atfi.st_uid) {
        err = NGX_ELOOP;
        goto failed;
    }

    return fd;

failed:

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", name);
    }

    ngx_set_errno(err);

    return NGX_INVALID_FILE;
}

#endif

/* 
 *	[analy]	���ļ��ķ�װ����
 */
static ngx_fd_t
ngx_open_file_wrapper(ngx_str_t *name, ngx_open_file_info_t *of,
    ngx_int_t mode, ngx_int_t create, ngx_int_t access, ngx_log_t *log)
{
    ngx_fd_t  fd;

#if !(NGX_HAVE_OPENAT)

    fd = ngx_open_file(name->data, mode, create, access);

    if (fd == NGX_INVALID_FILE) {
        of->err = ngx_errno;
        of->failed = ngx_open_file_n;
        return NGX_INVALID_FILE;
    }

    return fd;

#else

    u_char           *p, *cp, *end;
    ngx_fd_t          at_fd;
    ngx_str_t         at_name;

    if (of->disable_symlinks == NGX_DISABLE_SYMLINKS_OFF) {

		//	name->data = "/usr/local/nginx/html/index.html"
        fd = ngx_open_file(name->data, mode, create, access);			//	open()

        if (fd == NGX_INVALID_FILE) {
            of->err = ngx_errno;
            of->failed = ngx_open_file_n;
            return NGX_INVALID_FILE;
        }

        return fd;
    }

    p = name->data;					//	ָ���ļ�·���ַ����Ŀ�ʼ��
    end = p + name->len;			//	ָ���ļ�·���ַ����Ľ�����

    at_name = *name;

    if (of->disable_symlinks_from) {

        cp = p + of->disable_symlinks_from;

        *cp = '\0';

        at_fd = ngx_open_file(p, NGX_FILE_SEARCH|NGX_FILE_NONBLOCK,
                              NGX_FILE_OPEN, 0);

        *cp = '/';

        if (at_fd == NGX_INVALID_FILE) {
            of->err = ngx_errno;
            of->failed = ngx_open_file_n;
            return NGX_INVALID_FILE;
        }

        at_name.len = of->disable_symlinks_from;
        p = cp + 1;

    } else if (*p == '/') {

        at_fd = ngx_open_file("/",												//	��Ŀ¼
                              NGX_FILE_SEARCH|NGX_FILE_NONBLOCK,
                              NGX_FILE_OPEN, 0);

        if (at_fd == NGX_INVALID_FILE) {
            of->err = ngx_errno;
            of->failed = ngx_openat_file_n;
            return NGX_INVALID_FILE;
        }

        at_name.len = 1;
        p++;

    } else {
        at_fd = NGX_AT_FDCWD;
    }

	//	ָ��ǰ pָ���Ѿ�ָ�����ļ�·���ַ�����"usr/local/nginx/html/index.html"����
    for ( ;; ) {
        cp = ngx_strlchr(p, end, '/');
        if (cp == NULL) {
            break;
        }

        if (cp == p) {
            p++;
            continue;
        }

        *cp = '\0';				//	��ʱpָ�����usr�ַ���

        if (of->disable_symlinks == NGX_DISABLE_SYMLINKS_NOTOWNER) {
            fd = ngx_openat_file_owner(at_fd, p,
                                       NGX_FILE_SEARCH|NGX_FILE_NONBLOCK,
                                       NGX_FILE_OPEN, 0, log);

        } else {
            fd = ngx_openat_file(at_fd, p,												//	openat(),
                           NGX_FILE_SEARCH|NGX_FILE_NONBLOCK|NGX_FILE_NOFOLLOW,
                           NGX_FILE_OPEN, 0);
        }

        *cp = '/';				//	����'/'

        if (fd == NGX_INVALID_FILE) {
            of->err = ngx_errno;
            of->failed = ngx_openat_file_n;
            goto failed;
        }

        if (at_fd != NGX_AT_FDCWD && ngx_close_file(at_fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%V\" failed", &at_name);
        }

        p = cp + 1;
        at_fd = fd;
        at_name.len = cp - at_name.data;
    }

    if (p == end) {

        /*
         * If pathname ends with a trailing slash, assume the last path
         * component is a directory and reopen it with requested flags;
         * if not, fail with ENOTDIR as per POSIX.
         *
         * We cannot rely on O_DIRECTORY in the loop above to check
         * that the last path component is a directory because
         * O_DIRECTORY doesn't work on FreeBSD 8.  Fortunately, by
         * reopening a directory, we don't depend on it at all.
         */

        fd = ngx_openat_file(at_fd, ".", mode, create, access);
        goto done;
    }

    if (of->disable_symlinks == NGX_DISABLE_SYMLINKS_NOTOWNER
        && !(create & (NGX_FILE_CREATE_OR_OPEN|NGX_FILE_TRUNCATE)))
    {
        fd = ngx_openat_file_owner(at_fd, p, mode, create, access, log);

    } else {
        fd = ngx_openat_file(at_fd, p, mode|NGX_FILE_NOFOLLOW, create, access);
    }

done:

    if (fd == NGX_INVALID_FILE) {
        of->err = ngx_errno;
        of->failed = ngx_openat_file_n;
    }

failed:

    if (at_fd != NGX_AT_FDCWD && ngx_close_file(at_fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", &at_name);
    }

    return fd;
#endif
}

/* 
 *	[analy]	��ȡ�ļ���Ϣ�ĺ���
 */
static ngx_int_t
ngx_file_info_wrapper(ngx_str_t *name, ngx_open_file_info_t *of,
    ngx_file_info_t *fi, ngx_log_t *log)
{
    ngx_int_t  rc;

#if !(NGX_HAVE_OPENAT)

	//	��ȡ�ļ���Ϣ
    rc = ngx_file_info(name->data, fi);				//	stat()

    if (rc == NGX_FILE_ERROR) {
        of->err = ngx_errno;
        of->failed = ngx_file_info_n;
        return NGX_FILE_ERROR;
    }

    return rc;

#else

    ngx_fd_t  fd;

    if (of->disable_symlinks == NGX_DISABLE_SYMLINKS_OFF) {

        rc = ngx_file_info(name->data, fi);			//	stat()

        if (rc == NGX_FILE_ERROR) {
            of->err = ngx_errno;
            of->failed = ngx_file_info_n;
            return NGX_FILE_ERROR;
        }

        return rc;
    }

    fd = ngx_open_file_wrapper(name, of, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK,
                               NGX_FILE_OPEN, 0, log);

    if (fd == NGX_INVALID_FILE) {
        return NGX_FILE_ERROR;
    }

    rc = ngx_fd_info(fd, fi);								//	fstat()

    if (rc == NGX_FILE_ERROR) {
        of->err = ngx_errno;
        of->failed = ngx_fd_info_n;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {				//	close
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", name);
    }

    return rc;
#endif
}

/* 
 *	[analy]	�����ļ�����ȡ�ļ���Ϣ
 */
static ngx_int_t
ngx_open_and_stat_file(ngx_str_t *name, ngx_open_file_info_t *of,
    ngx_log_t *log)
{
    ngx_fd_t         fd;
    ngx_file_info_t  fi;

    if (of->fd != NGX_INVALID_FILE) {			
		
		//	����ļ��Ѿ��򿪣�ֱ�ӻ�ȡ�ļ���Ϣ�����Ƚ�inode�ڵ��Ƿ����仯��
		//	��������仯˵���ļ����ı䣬��Ҫ���´򿪼���cache
        if (ngx_file_info_wrapper(name, of, &fi, log) == NGX_FILE_ERROR) {
            of->fd = NGX_INVALID_FILE;
            return NGX_ERROR;
        }

        if (of->uniq == ngx_file_uniq(&fi)) {
            goto done;
        }

    } else if (of->test_dir) {

        if (ngx_file_info_wrapper(name, of, &fi, log) == NGX_FILE_ERROR) {
            of->fd = NGX_INVALID_FILE;
            return NGX_ERROR;
        }

        if (ngx_is_dir(&fi)) {
            goto done;
        }
    }

    if (!of->log) {		//	������־�ļ�ʱ

        /*
         * Use non-blocking open() not to hang on FIFO files, etc.
         * This flag has no effect on a regular files.
         */

        fd = ngx_open_file_wrapper(name, of, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK,				//	���ļ�
                                   NGX_FILE_OPEN, 0, log);

    } else {
		//	����־�ļ��Ĵ�����׷���ļ�ĩβ�ķ�ʽ��
        fd = ngx_open_file_wrapper(name, of, NGX_FILE_APPEND,
                                   NGX_FILE_CREATE_OR_OPEN,
                                   NGX_FILE_DEFAULT_ACCESS, log);
    }

    if (fd == NGX_INVALID_FILE) {
        of->fd = NGX_INVALID_FILE;
        return NGX_ERROR;
    }

	//	��ȡ�ļ���Ϣ
    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {						//	fstat()
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      ngx_fd_info_n " \"%V\" failed", name);

		//	���fstatʧ�ܣ����ر��ļ�
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%V\" failed", name);
        }

        of->fd = NGX_INVALID_FILE;

        return NGX_ERROR;
    }

    if (ngx_is_dir(&fi)) {									//	Ŀ¼ʱ���ر�Ŀ¼������
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%V\" failed", name);
        }

        of->fd = NGX_INVALID_FILE;

    } else {
        of->fd = fd;

        if (of->read_ahead && ngx_file_size(&fi) > NGX_MIN_READ_AHEAD) {
            if (ngx_read_ahead(fd, of->read_ahead) == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                              ngx_read_ahead_n " \"%V\" failed", name);
            }
        }

        if (of->directio <= ngx_file_size(&fi)) {
            if (ngx_directio_on(fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                              ngx_directio_on_n " \"%V\" failed", name);

            } else {
                of->is_directio = 1;
            }
        }
    }

done:

    of->uniq = ngx_file_uniq(&fi);					//	�����ļ���Ϣ
    of->mtime = ngx_file_mtime(&fi);
    of->size = ngx_file_size(&fi);
    of->fs_size = ngx_file_fs_size(&fi);
    of->is_dir = ngx_is_dir(&fi);
    of->is_file = ngx_is_file(&fi);
    of->is_link = ngx_is_link(&fi);
    of->is_exec = ngx_is_exec(&fi);

    return NGX_OK;
}


/*
 * we ignore any possible event setting error and
 * fallback to usual periodic file retests
 */

static void
ngx_open_file_add_event(ngx_open_file_cache_t *cache,
    ngx_cached_open_file_t *file, ngx_open_file_info_t *of, ngx_log_t *log)
{
    ngx_open_file_cache_event_t  *fev;

    if (!(ngx_event_flags & NGX_USE_VNODE_EVENT)				//	���û��ʹ��kqueue, �˺���������ִ��
        || !of->events
        || file->event
        || of->fd == NGX_INVALID_FILE
        || file->uses < of->min_uses)
    {
        return;
    }

    file->use_event = 0;

    file->event = ngx_calloc(sizeof(ngx_event_t), log);
    if (file->event== NULL) {
        return;
    }

    fev = ngx_alloc(sizeof(ngx_open_file_cache_event_t), log);
    if (fev == NULL) {
        ngx_free(file->event);
        file->event = NULL;
        return;
    }

    fev->fd = of->fd;
    fev->file = file;
    fev->cache = cache;

    file->event->handler = ngx_open_file_cache_remove;
    file->event->data = fev;

    /*
     * although vnode event may be called while ngx_cycle->poll
     * destruction, however, cleanup procedures are run before any
     * memory freeing and events will be canceled.
     */

    file->event->log = ngx_cycle->log;

    if (ngx_add_event(file->event, NGX_VNODE_EVENT, NGX_ONESHOT_EVENT)
        != NGX_OK)
    {
        ngx_free(file->event->data);
        ngx_free(file->event);
        file->event = NULL;
        return;
    }

    /*
     * we do not set file->use_event here because there may be a race
     * condition: a file may be deleted between opening the file and
     * adding event, so we rely upon event notification only after
     * one file revalidation on next file access
     */

    return;
}


static void
ngx_open_file_cleanup(void *data)
{
    ngx_open_file_cache_cleanup_t  *c = data;							//	��ȡ�� ngx_pool_cleanup_add() �����������ṹָ��

    c->file->count--;													//	����Ӧ��cache�ļ����ü�����һ

    ngx_close_cached_file(c->cache, c->file, c->min_uses, c->log);

    /* drop one or two expired open files */
    ngx_expire_old_cached_files(c->cache, 1, c->log);					//	ɾ�����ڵ��ļ�����ָ�� "open_file_cache" ��inactive���õ�ʱ�䣬Ĭ��60s
}


static void
ngx_close_cached_file(ngx_open_file_cache_t *cache,
    ngx_cached_open_file_t *file, ngx_uint_t min_uses, ngx_log_t *log)
{
    ngx_log_debug5(NGX_LOG_DEBUG_CORE, log, 0,
                   "close cached open file: %s, fd:%d, c:%d, u:%d, %d",
                   file->name, file->fd, file->count, file->uses, file->close);

    if (!file->close) {

        file->accessed = ngx_time();

		//	���ڵ������������ɾ��
        ngx_queue_remove(&file->queue);
	
		//	�ڽ����в��� expire_queue ���е��ײ�
        ngx_queue_insert_head(&cache->expire_queue, &file->queue);

		//	���cache�ļ���ʹ�ô����Ƿ�������õ�cache�ļ���Сʹ�ô�������cache�ļ����������õĴ����Ƿ����0��
		//	�������������ϣ�����Ҫ��ϵ�ļ�
        if (file->uses >= min_uses || file->count) {
            return;
        }
    }

    ngx_open_file_del_event(file);						//	epoll��ʹ�ô˺���

	//	cache�ļ����������õĴ�������0�������ر��ļ�
    if (file->count) {			
        return;
    }

	//	�ļ��������򿪺󽫵���close�ر�
    if (file->fd != NGX_INVALID_FILE) {					

        if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", file->name);
        }

        file->fd = NGX_INVALID_FILE;
    }

    if (!file->close) {
        return;
    }

    ngx_free(file->name);			//	�ͷ�cache�ļ�������ռ�õĿռ䣨ngx_open_cached_file()����������ռ䣬δ���ڴ�������룩
    ngx_free(file);					//	�ͷ�cache�ļ�ռ�õĿռ䣨ngx_open_cached_file()����������ռ䣬δ���ڴ�������룩
}

/* 
 *	[analy]	epollû��ʹ�ô˺���
 */
static void
ngx_open_file_del_event(ngx_cached_open_file_t *file)
{
    if (file->event == NULL) {
        return;
    }

    (void) ngx_del_event(file->event, NGX_VNODE_EVENT,
                         file->count ? NGX_FLUSH_EVENT : NGX_CLOSE_EVENT);

    ngx_free(file->event->data);
    ngx_free(file->event);
    file->event = NULL;
    file->use_event = 0;
}

/* 
 *	[analy]	ɾ�����ڵ�cache�ļ�
 */
static void
ngx_expire_old_cached_files(ngx_open_file_cache_t *cache, ngx_uint_t n,
    ngx_log_t *log)
{
    time_t                   now;
    ngx_queue_t             *q;
    ngx_cached_open_file_t  *file;

    now = ngx_time();

    /*
     * n == 1 deletes one or two inactive files
     * n == 0 deletes least recently used file by force
     *        and one or two inactive files
     */

    while (n < 3) {

		//	expire_queue�����ǿգ���ֱ�ӷ���
        if (ngx_queue_empty(&cache->expire_queue)) {			
            return;
        }

		//	ȡ��expire_queue���е����һ���ڵ㣬Ҳ���ǿ�����Ҫ����ʱ���ļ�(��Ϊβ�����ʱ��û�в������ļ�)
        q = ngx_queue_last(&cache->expire_queue);

		//	��ȡ�ýڵ�������cache�ļ�
        file = ngx_queue_data(q, ngx_cached_open_file_t, queue);

		//	���n������Ϊ0����ǿ��ɾ��һ���������ʹ�õ��ļ���֮�����inactiveʱ������Ƿ�ɾ���ļ������ɾ�������ļ���
		//	���n������Ϊ1��������inactiveʱ������Ƿ�ɾ���ļ������ɾ�������ļ�
        if (n++ != 0 && now - file->accessed <= cache->inactive) {
            return;
        }

		//	���ڵ������������ɾ��(�� expire_queue ����)
        ngx_queue_remove(q);

		//	���ҽ���cache�ļ��Ӻ������Ҳɾ����
        ngx_rbtree_delete(&cache->rbtree, &file->node);

		//	��ǰcache���ܸ�����һ
        cache->current--;

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
                       "expire cached open file: %s", file->name);

        if (!file->err && !file->is_dir) {						//	�������Ŀ¼����close()���ļ�
            file->close = 1;
			ngx_close_cached_file(cache, file, 0, log);

        } else {
            ngx_free(file->name);
            ngx_free(file);
        }
    }
}


static void
ngx_open_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_cached_open_file_t    *file, *file_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            file = (ngx_cached_open_file_t *) node;
            file_temp = (ngx_cached_open_file_t *) temp;

            p = (ngx_strcmp(file->name, file_temp->name) < 0)
                    ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_cached_open_file_t *
ngx_open_file_lookup(ngx_open_file_cache_t *cache, ngx_str_t *name,
    uint32_t hash)
{
    ngx_int_t                rc;
    ngx_rbtree_node_t       *node, *sentinel;
    ngx_cached_open_file_t  *file;

    node = cache->rbtree.root;
    sentinel = cache->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        file = (ngx_cached_open_file_t *) node;

        rc = ngx_strcmp(name->data, file->name);

        if (rc == 0) {
            return file;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

//	epoll�в�ʹ�ô˺���
static void
ngx_open_file_cache_remove(ngx_event_t *ev)
{
    ngx_cached_open_file_t       *file;
    ngx_open_file_cache_event_t  *fev;

    fev = ev->data;
    file = fev->file;

    ngx_queue_remove(&file->queue);

    ngx_rbtree_delete(&fev->cache->rbtree, &file->node);

    fev->cache->current--;

    /* NGX_ONESHOT_EVENT was already deleted */
    file->event = NULL;
    file->use_event = 0;

    file->close = 1;

    ngx_close_cached_file(fev->cache, file, 0, ev->log);

    /* free memory only when fev->cache and fev->file are already not needed */

    ngx_free(ev->data);
    ngx_free(ev);
}
