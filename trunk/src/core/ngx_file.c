
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_atomic_t   temp_number = 0;
ngx_atomic_t         *ngx_temp_number = &temp_number;
ngx_atomic_int_t      ngx_random_number = 123456;


//	дchain���ݵ���ʱ�ļ���
ssize_t
ngx_write_chain_to_temp_file(ngx_temp_file_t *tf, ngx_chain_t *chain)
{
    ngx_int_t  rc;

    if (tf->file.fd == NGX_INVALID_FILE) {

		//	������ʱ�ļ�
        rc = ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                  tf->persistent, tf->clean, tf->access);

        if (rc == NGX_ERROR || rc == NGX_AGAIN) {
            return rc;
        }

        if (tf->log_level) {
            ngx_log_error(tf->log_level, tf->file.log, 0, "%s %V",
                          tf->warn, &tf->file.name);
        }
    }

	//	дchain���ݵ��ļ���
    return ngx_write_chain_to_file(&tf->file, chain, tf->offset, tf->pool);
}

/*
 *	������ʱ�ļ���������Ŀ¼�Ĵ���
 */
ngx_int_t
ngx_create_temp_file(ngx_file_t *file, ngx_path_t *path, ngx_pool_t *pool,
    ngx_uint_t persistent, ngx_uint_t clean, ngx_uint_t access)
{
    uint32_t                  n;
    ngx_err_t                 err;
    ngx_pool_cleanup_t       *cln;
    ngx_pool_cleanup_file_t  *clnf;

	//	�����ļ����Ƴ���(·������+��/��+��Ŀ¼�ĳ���+�ļ������ȣ�10��)
    file->name.len = path->name.len + 1 + path->len + 10;			//	·�������ǲ�������/����β�ģ�

    file->name.data = ngx_pnalloc(pool, file->name.len + 1);
    if (file->name.data == NULL) {
        return NGX_ERROR;
    }

#if 0
    for (i = 0; i < file->name.len; i++) {
         file->name.data[i] = 'X';
    }
#endif

	//	����·������
    ngx_memcpy(file->name.data, path->name.data, path->name.len);

	//	��ȡ�����
    n = (uint32_t) ngx_next_temp_number(0);

    cln = ngx_pool_cleanup_add(pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    for ( ;; ) {

		//	�����ļ���
        (void) ngx_sprintf(file->name.data + path->name.len + 1 + path->len,
                           "%010uD%Z", n);

		//	������Ŀ¼��
        ngx_create_hashed_filename(path, file->name.data, file->name.len);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "hashed path: %s", file->name.data);

		//	������ʱ�ļ�
        file->fd = ngx_open_tempfile(file->name.data, persistent, access);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "temp fd:%d", file->fd);

		//	�ļ������ɹ�
        if (file->fd != NGX_INVALID_FILE) {

            cln->handler = clean ? ngx_pool_delete_file : ngx_pool_cleanup_file;
            clnf = cln->data;		//	�Ѿ��ں���ngx_pool_cleanup_add����������ռ�

            clnf->fd = file->fd;
            clnf->name = file->name.data;
            clnf->log = pool->log;

            return NGX_OK;
        }

        err = ngx_errno;

		//	����ļ��Ѿ����ڣ������������ļ����������ļ�
        if (err == NGX_EEXIST) {
            n = (uint32_t) ngx_next_temp_number(1);
            continue;
        }

        if ((path->level[0] == 0) || (err != NGX_ENOPATH)) {
            ngx_log_error(NGX_LOG_CRIT, file->log, err,
                          ngx_open_tempfile_n " \"%s\" failed",
                          file->name.data);
            return NGX_ERROR;
        }

		//	ѭ��������Ŀ¼
        if (ngx_create_path(file, path) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }		//	END FOR
}

/*
 *	����hash�ļ�����������Ŀ¼����
 *	����	
 *		����ļ����ƣ�00000123456
 *		��Ŀ¼���ƣ�1��2��3��Ŀ¼λ���ֱ���2|1|2����/56/4/23/
 *		��Ŀ¼�����ɹ����Ǵ�����ļ����Ƶ�ĩβ��ʼ��ȡָ��ָ����λ��
 */
void
ngx_create_hashed_filename(ngx_path_t *path, u_char *file, size_t len)
{
    size_t      i, level;
    ngx_uint_t  n;

    i = path->name.len + 1;

    file[path->name.len + path->len]  = '/';

    for (n = 0; n < 3; n++) {
        level = path->level[n];

        if (level == 0) {
            break;
        }

        len -= level;
        file[i - 1] = '/';
        ngx_memcpy(&file[i], &file[len], level);
        i += level + 1;
    }
}

//	ѭ��������Ŀ¼
ngx_int_t
ngx_create_path(ngx_file_t *file, ngx_path_t *path)
{
    size_t      pos;
    ngx_err_t   err;
    ngx_uint_t  i;

    pos = path->name.len;

	//	ѭ��������Ŀ¼
    for (i = 0; i < 3; i++) {
        if (path->level[i] == 0) {
            break;
        }

        pos += path->level[i] + 1;

        file->name.data[pos] = '\0';

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "temp file: \"%s\"", file->name.data);

        if (ngx_create_dir(file->name.data, 0700) == NGX_FILE_ERROR) {
            err = ngx_errno;
            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_CRIT, file->log, err,
                              ngx_create_dir_n " \"%s\" failed",
                              file->name.data);
                return NGX_ERROR;
            }
        }

        file->name.data[pos] = '/';
    }

    return NGX_OK;
}


ngx_err_t
ngx_create_full_path(u_char *dir, ngx_uint_t access)
{
    u_char     *p, ch;
    ngx_err_t   err;

    err = 0;

#if (NGX_WIN32)
    p = dir + 3;
#else
    p = dir + 1;
#endif

    for ( /* void */ ; *p; p++) {
        ch = *p;

        if (ch != '/') {
            continue;
        }

        *p = '\0';

        if (ngx_create_dir(dir, access) == NGX_FILE_ERROR) {
            err = ngx_errno;

            switch (err) {
            case NGX_EEXIST:
                err = 0;
            case NGX_EACCES:
                break;

            default:
                return err;
            }
        }

        *p = '/';
    }

    return err;
}


ngx_atomic_uint_t
ngx_next_temp_number(ngx_uint_t collision)
{
    ngx_atomic_uint_t  n, add;

    add = collision ? ngx_random_number : 1;

    n = ngx_atomic_fetch_add(ngx_temp_number, add);

    return n + add;
}


char *
ngx_conf_set_path_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ssize_t      level;
    ngx_str_t   *value;
    ngx_uint_t   i, n;
    ngx_path_t  *path, **slot;

    slot = (ngx_path_t **) (p + cmd->offset);

    if (*slot) {
        return "is duplicate";
    }

    path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (path == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    path->name = value[1];

    if (path->name.data[path->name.len - 1] == '/') {			//	���Ŀ¼�� '/' ��β���򲻽� '/'������·���ļ�����
        path->name.len--;
    }

	//	����Ƿ�Ϊ����·����������ǽ����ϵͳ����·��
    if (ngx_conf_full_name(cf->cycle, &path->name, 0) != NGX_OK) {
        return NULL;
    }

    path->len = 0;
    path->manager = NULL;
    path->loader = NULL;
	path->conf_file = cf->conf_file->file.name.data;
	path->line = cf->conf_file->line;

	//	����Ƿ��к��������� ��������������level
    for (i = 0, n = 2; n < cf->args->nelts; i++, n++) {
        level = ngx_atoi(value[n].data, value[n].len);
        if (level == NGX_ERROR || level == 0) {
            return "invalid value";
        }

        path->level[i] = level;
        path->len += level + 1;			//	������Ŀ¼���ļ����Ƴ��ȴ�С
    }

    while (i < 3) {						//	δ��ָ������ʾָ���ļ��� ����Ĭ�ϵ�·������Ϊ0
        path->level[i++] = 0;
    }

    *slot = path;

	//	���� path �� cf->cycle->pathes ������
    if (ngx_add_path(cf, slot) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
 *	[analy]	�ϲ�ָ�� "proxy_temp_path" ָ����·���� �����ָ����http��server��location�о�δָ������ʹ��initĬ��ֵ
 *			1. ��Ͳ�������õ�ָ����Ǹ߲�ָ��
 *			2. ����Ͳ����δ����ָ����̳��ϲ�ָ��������
 *	 ��ִ��configure����ʱ��ָ��ѡ����δָ������ʹ������Ĭ��ֵ��
 *	 NGX_HTTP_FASTCGI_TEMP_PATH  -fastcgi_temp
 *	 NGX_HTTP_PROXY_TEMP_PATH	 -proxy_temp
 *	 NGX_HTTP_SCGI_TEMP_PATH	 -scgi_temp
 *	 NGX_HTTP_UWSGI_TEMP_PATH	 -uwsgi_temp
 *	 NGX_HTTP_CLIENT_TEMP_PATH	 -client_body_temp
 */
char *
ngx_conf_merge_path_value(ngx_conf_t *cf, ngx_path_t **path, ngx_path_t *prev,
    ngx_path_init_t *init)
{
	
	//	�������ָ����·���� �ϲ��Ƿ����þ���Ӱ�챾�㡣�������δ���ã���ʹ���ϲ��������
	//	(e.g. http block { set path; location { set path } } location�еĽ��滻��http�����õ�·��)
    if (*path) {
        return NGX_CONF_OK;
    }

    if (prev) {
        *path = prev;
        return NGX_CONF_OK;
    }

	//	�������ָ��δָ�� path�� �����´���
    *path = ngx_palloc(cf->pool, sizeof(ngx_path_t));
    if (*path == NULL) {
        return NGX_CONF_ERROR;
    }

    (*path)->name = init->name;

	//	����ʼ����·���Ƿ�Ϊ����·�������ǽ����ϵͳָ��·��
    if (ngx_conf_full_name(cf->cycle, &(*path)->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    (*path)->level[0] = init->level[0];
    (*path)->level[1] = init->level[1];
    (*path)->level[2] = init->level[2];

    (*path)->len = init->level[0] + (init->level[0] ? 1 : 0)
                   + init->level[1] + (init->level[1] ? 1 : 0)
                   + init->level[2] + (init->level[2] ? 1 : 0);

    (*path)->manager = NULL;
    (*path)->loader = NULL;
    (*path)->conf_file = NULL;

    if (ngx_add_path(cf, path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char *
ngx_conf_set_access_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *confp = conf;

    u_char      *p;
    ngx_str_t   *value;
    ngx_uint_t   i, right, shift, *access;

    access = (ngx_uint_t *) (confp + cmd->offset);

    if (*access != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *access = 0600;

    for (i = 1; i < cf->args->nelts; i++) {

        p = value[i].data;

        if (ngx_strncmp(p, "user:", sizeof("user:") - 1) == 0) {
            shift = 6;
            p += sizeof("user:") - 1;

        } else if (ngx_strncmp(p, "group:", sizeof("group:") - 1) == 0) {
            shift = 3;
            p += sizeof("group:") - 1;

        } else if (ngx_strncmp(p, "all:", sizeof("all:") - 1) == 0) {
            shift = 0;
            p += sizeof("all:") - 1;

        } else {
            goto invalid;
        }

        if (ngx_strcmp(p, "rw") == 0) {
            right = 6;

        } else if (ngx_strcmp(p, "r") == 0) {
            right = 4;

        } else {
            goto invalid;
        }

        *access |= right << shift;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}

/* 
 *	���� ngx_path_t �� cf->cycle->pathes ������
 */
ngx_int_t
ngx_add_path(ngx_conf_t *cf, ngx_path_t **slot)
{
    ngx_uint_t   i, n;
    ngx_path_t  *path, **p;

    path = *slot;

    p = cf->cycle->pathes.elts;
    for (i = 0; i < cf->cycle->pathes.nelts; i++) {
        if (p[i]->name.len == path->name.len							//	���path->name�Ƿ����
            && ngx_strcmp(p[i]->name.data, path->name.data) == 0)
        {
            for (n = 0; n < 3; n++) {
                if (p[i]->level[n] != path->level[n]) {
                    if (path->conf_file == NULL) {
                        if (p[i]->conf_file == NULL) {
                            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                      "the default path name \"%V\" has "
                                      "the same name as another default path, "
                                      "but the different levels, you need to "
                                      "redefine one of them in http section",
                                      &p[i]->name);
                            return NGX_ERROR;
                        }

                        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                      "the path name \"%V\" in %s:%ui has "
                                      "the same name as default path, but "
                                      "the different levels, you need to "
                                      "define default path in http section",
                                      &p[i]->name, p[i]->conf_file, p[i]->line);
                        return NGX_ERROR;
                    }

                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                      "the same path name \"%V\" in %s:%ui "
                                      "has the different levels than",
                                      &p[i]->name, p[i]->conf_file, p[i]->line);
                    return NGX_ERROR;
                }

                if (p[i]->level[n] == 0) {
                    break;
                }
            }

            *slot = p[i];

            return NGX_OK;
        }
    }

	//	���Ӳ��� *slot �� cf->cycle->pathes ������
    p = ngx_array_push(&cf->cycle->pathes);
    if (p == NULL) {
        return NGX_ERROR;
    }

    *p = path;

    return NGX_OK;
}


/* 
 *	����cycle->pathes�д�ŵ�Ŀ¼�������ļ������ߺ��ļ�������Ȩ��
 */
ngx_int_t
ngx_create_pathes(ngx_cycle_t *cycle, ngx_uid_t user)
{
    ngx_err_t         err;
    ngx_uint_t        i;
    ngx_path_t      **path;

    path = cycle->pathes.elts;
    for (i = 0; i < cycle->pathes.nelts; i++) {

        if (ngx_create_dir(path[i]->name.data, 0700) == NGX_FILE_ERROR) {			//	����Ŀ¼
            err = ngx_errno;
            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, err,
                              ngx_create_dir_n " \"%s\" failed",
                              path[i]->name.data);
                return NGX_ERROR;
            }
        }


		//	���ָ����userʱ�����ı�Ŀ¼����������Ϣ
        if (user == (ngx_uid_t) NGX_CONF_UNSET_UINT) {
            continue;
        }

#if !(NGX_WIN32)
        {
        ngx_file_info_t   fi;

        if (ngx_file_info((const char *) path[i]->name.data, &fi)					//	��ȡ�ļ���Ϣ
            == NGX_FILE_ERROR)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          ngx_file_info_n " \"%s\" failed", path[i]->name.data);
            return NGX_ERROR;
        }

        if (fi.st_uid != user) {													//	��������ڲ����д��ݵ�uid���޸��ļ�own; group����
            if (chown((const char *) path[i]->name.data, user, -1) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "chown(\"%s\", %d) failed",
                              path[i]->name.data, user);
                return NGX_ERROR;
            }
        }

        if ((fi.st_mode & (S_IRUSR|S_IWUSR|S_IXUSR))								//	������Ŀ¼owner�鲻��rwxȨ��ʱ�������rwxȨ��
                                                  != (S_IRUSR|S_IWUSR|S_IXUSR))
        {
            fi.st_mode |= (S_IRUSR|S_IWUSR|S_IXUSR);

            if (chmod((const char *) path[i]->name.data, fi.st_mode) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "chmod() \"%s\" failed", path[i]->name.data);
                return NGX_ERROR;
            }
        }
        }
#endif
    }

    return NGX_OK;
}


ngx_int_t
ngx_ext_rename_file(ngx_str_t *src, ngx_str_t *to, ngx_ext_rename_file_t *ext)
{
    u_char           *name;
    ngx_err_t         err;
    ngx_copy_file_t   cf;

#if !(NGX_WIN32)

    if (ext->access) {

		//	�ı��ļ��ķ���Ȩ��
        if (ngx_change_file_access(src->data, ext->access) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
                          ngx_change_file_access_n " \"%s\" failed", src->data);
            err = 0;
            goto failed;
        }
    }

#endif

    if (ext->time != -1) {

		//	�����ļ�������޸�ʱ�䣨mtime)
        if (ngx_set_file_time(src->data, ext->fd, ext->time) != NGX_OK) {
            ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
                          ngx_set_file_time_n " \"%s\" failed", src->data);
            err = 0;
            goto failed;
        }
    }

	//	�����ļ�����
    if (ngx_rename_file(src->data, to->data) != NGX_FILE_ERROR) {
        return NGX_OK;
    }

    err = ngx_errno;

    if (err == NGX_ENOPATH) {		/* No such file or directory */

		//	����rename���������ļ�ʱ�����Ŀ¼�����ڣ������� create_path ��Ǽ���Ƿ���Ҫ����Ŀ¼
        if (!ext->create_path) {
            goto failed;
        }

		//	����Ŀ¼
        err = ngx_create_full_path(to->data, ngx_dir_access(ext->path_access));

        if (err) {
            ngx_log_error(NGX_LOG_CRIT, ext->log, err,
                          ngx_create_dir_n " \"%s\" failed", to->data);
            err = 0;
            goto failed;
        }

		//	rename()
        if (ngx_rename_file(src->data, to->data) != NGX_FILE_ERROR) {
            return NGX_OK;
        }

        err = ngx_errno;
    }

#if (NGX_WIN32)

    if (err == NGX_EEXIST) {
        err = ngx_win32_rename_file(src, to, ext->log);

        if (err == 0) {
            return NGX_OK;
        }
    }

#endif

    if (err == NGX_EXDEV) {

        cf.size = -1;
        cf.buf_size = 0;
        cf.access = ext->access;
        cf.time = ext->time;
        cf.log = ext->log;

        name = ngx_alloc(to->len + 1 + 10 + 1, ext->log);
        if (name == NULL) {
            return NGX_ERROR;
        }

        (void) ngx_sprintf(name, "%*s.%010uD%Z", to->len, to->data,
                           (uint32_t) ngx_next_temp_number(0));

        if (ngx_copy_file(src->data, name, &cf) == NGX_OK) {

            if (ngx_rename_file(name, to->data) != NGX_FILE_ERROR) {
                ngx_free(name);

                if (ngx_delete_file(src->data) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
                                  ngx_delete_file_n " \"%s\" failed",
                                  src->data);
                    return NGX_ERROR;
                }

                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
                          ngx_rename_file_n " \"%s\" to \"%s\" failed",
                          name, to->data);

            if (ngx_delete_file(name) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
                              ngx_delete_file_n " \"%s\" failed", name);

            }
        }

        ngx_free(name);

        err = 0;
    }

failed:

    if (ext->delete_file) {
        if (ngx_delete_file(src->data) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
                          ngx_delete_file_n " \"%s\" failed", src->data);
        }
    }

    if (err) {
        ngx_log_error(NGX_LOG_CRIT, ext->log, err,
                      ngx_rename_file_n " \"%s\" to \"%s\" failed",
                      src->data, to->data);
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_copy_file(u_char *from, u_char *to, ngx_copy_file_t *cf)
{
    char             *buf;
    off_t             size;
    size_t            len;
    ssize_t           n;
    ngx_fd_t          fd, nfd;
    ngx_int_t         rc;
    ngx_file_info_t   fi;

    rc = NGX_ERROR;
    buf = NULL;
    nfd = NGX_INVALID_FILE;

    fd = ngx_open_file(from, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", from);
        goto failed;
    }

    if (cf->size != -1) {
        size = cf->size;

    } else {
        if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", from);

            goto failed;
        }

        size = ngx_file_size(&fi);
    }

    len = cf->buf_size ? cf->buf_size : 65536;

    if ((off_t) len > size) {
        len = (size_t) size;
    }

    buf = ngx_alloc(len, cf->log);
    if (buf == NULL) {
        goto failed;
    }

    nfd = ngx_open_file(to, NGX_FILE_WRONLY, NGX_FILE_CREATE_OR_OPEN,
                        cf->access);

    if (nfd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", to);
        goto failed;
    }

    while (size > 0) {

        if ((off_t) len > size) {
            len = (size_t) size;
        }

        n = ngx_read_fd(fd, buf, len);

        if (n == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_read_fd_n " \"%s\" failed", from);
            goto failed;
        }

        if ((size_t) n != len) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_read_fd_n " has read only %z of %uz from %s",
                          n, size, from);
            goto failed;
        }

        n = ngx_write_fd(nfd, buf, len);

        if (n == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_write_fd_n " \"%s\" failed", to);
            goto failed;
        }

        if ((size_t) n != len) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_write_fd_n " has written only %z of %uz to %s",
                          n, size, to);
            goto failed;
        }

        size -= n;
    }

    if (cf->time != -1) {
        if (ngx_set_file_time(to, nfd, cf->time) != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_set_file_time_n " \"%s\" failed", to);
            goto failed;
        }
    }

    rc = NGX_OK;

failed:

    if (nfd != NGX_INVALID_FILE) {
        if (ngx_close_file(nfd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", to);
        }
    }

    if (fd != NGX_INVALID_FILE) {
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", from);
        }
    }

    if (buf) {
        ngx_free(buf);
    }

    return rc;
}


/*
 * ctx->init_handler() - see ctx->alloc
 * ctx->file_handler() - file handler
 * ctx->pre_tree_handler() - handler is called before entering directory
 * ctx->post_tree_handler() - handler is called after leaving directory
 * ctx->spec_handler() - special (socket, FIFO, etc.) file handler
 *
 * ctx->data - some data structure, it may be the same on all levels, or
 *     reallocated if ctx->alloc is nonzero
 *
 * ctx->alloc - a size of data structure that is allocated at every level
 *     and is initilialized by ctx->init_handler()
 *
 * ctx->log - a log
 *
 * on fatal (memory) error handler must return NGX_ABORT to stop walking tree
 */

ngx_int_t
ngx_walk_tree(ngx_tree_ctx_t *ctx, ngx_str_t *tree)
{
    void       *data, *prev;
    u_char     *p, *name;
    size_t      len;
    ngx_int_t   rc;
    ngx_err_t   err;
    ngx_str_t   file, buf;
    ngx_dir_t   dir;

    ngx_str_null(&buf);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "walk tree \"%V\"", tree);

	//	��Ŀ¼
    if (ngx_open_dir(tree, &dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_open_dir_n " \"%s\" failed", tree->data);
        return NGX_ERROR;
    }

    prev = ctx->data;

    if (ctx->alloc) {
        data = ngx_alloc(ctx->alloc, ctx->log);
        if (data == NULL) {
            goto failed;
        }

        if (ctx->init_handler(data, prev) == NGX_ABORT) {
            goto failed;
        }

        ctx->data = data;

    } else {
        data = NULL;
    }

    for ( ;; ) {

        ngx_set_errno(0);

		//	��ȡĿ¼��
        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;

            if (err == NGX_ENOMOREFILES) {
                rc = NGX_OK;

            } else {
                ngx_log_error(NGX_LOG_CRIT, ctx->log, err,
                              ngx_read_dir_n " \"%s\" failed", tree->data);
                rc = NGX_ERROR;
            }

            goto done;
        }

        len = ngx_de_namelen(&dir);			//	�ļ�������
        name = ngx_de_name(&dir);			//	�ļ����ַ���

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                      "tree name %uz:\"%s\"", len, name);

        if (len == 1 && name[0] == '.') {
            continue;
        }

        if (len == 2 && name[0] == '.' && name[1] == '.') {
            continue;
        }

        file.len = tree->len + 1 + len;				//	ƴװ �ļ����ܳ���

        if (file.len + NGX_DIR_MASK_LEN > buf.len) {

            if (buf.len) {
                ngx_free(buf.data);
            }

            buf.len = tree->len + 1 + len + NGX_DIR_MASK_LEN;

            buf.data = ngx_alloc(buf.len + 1, ctx->log);
            if (buf.data == NULL) {
                goto failed;
            }
        }

		//	��������·����buf
        p = ngx_cpymem(buf.data, tree->data, tree->len);
        *p++ = '/';
        ngx_memcpy(p, name, len + 1);

        file.data = buf.data;

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                       "tree path \"%s\"", file.data);

        if (!dir.valid_info) {

			//	��ȡĿ¼����ļ���Ϣ
            if (ngx_de_info(file.data, &dir) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                              ngx_de_info_n " \"%s\" failed", file.data);
                continue;
            }
        }


        if (ngx_de_is_file(&dir)) {

			//	�����ļ�

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree file \"%s\"", file.data);

            ctx->size = ngx_de_size(&dir);
            ctx->fs_size = ngx_de_fs_size(&dir);
            ctx->access = ngx_de_access(&dir);
            ctx->mtime = ngx_de_mtime(&dir);

			//	e.g. ngx_http_file_cache_manage_file()
            if (ctx->file_handler(ctx, &file) == NGX_ABORT) {
                goto failed;
            }

        } else if (ngx_de_is_dir(&dir)) {

			//	��Ŀ¼

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree enter dir \"%s\"", file.data);

            ctx->access = ngx_de_access(&dir);
            ctx->mtime = ngx_de_mtime(&dir);

			//	e.g. ngx_http_file_cache_noop
            if (ctx->pre_tree_handler(ctx, &file) == NGX_ABORT) {
                goto failed;
            }

			//	�ݹ����Ŀ¼�е��ļ�
            if (ngx_walk_tree(ctx, &file) == NGX_ABORT) {
                goto failed;
            }

            ctx->access = ngx_de_access(&dir);
            ctx->mtime = ngx_de_mtime(&dir);

			//	e.g. ngx_http_file_cache_noop
            if (ctx->post_tree_handler(ctx, &file) == NGX_ABORT) {
                goto failed;
            }

        } else {

			//	���ļ���Ŀ¼��ֱ��ɾ����
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree special \"%s\"", file.data);

			//	e.g. ngx_http_file_cache_delete_file()
            if (ctx->spec_handler(ctx, &file) == NGX_ABORT) {
                goto failed;
            }
        }
    }		//	end for

failed:

    rc = NGX_ABORT;

done:

    if (buf.len) {
        ngx_free(buf.data);
    }

    if (data) {
        ngx_free(data);
        ctx->data = prev;
    }

	//	�ر�Ŀ¼
    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_close_dir_n " \"%s\" failed", tree->data);
    }

    return rc;
}
