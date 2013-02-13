
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     16384
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {	
    void                     *data;				//	e.g. 在函数 ngx_http_file_cache_set_slot（） 被设置成 ngx_http_file_cache_t 
    ngx_shm_t                 shm;				//	共享内存属性
    ngx_shm_zone_init_pt      init;				//	e.g. 在函数 ngx_http_file_cache_set_slot（） 被设置成  ngx_http_file_cache_init()
    void                     *tag;				//	使用共享内存的模块名称（内存地址）
};


struct ngx_cycle_s {
    void                  ****conf_ctx;								/* [analy]	模块配置结构指针数组(含所有模块)   */
    ngx_pool_t               *pool;									/* [analy]	内存池   */

    ngx_log_t                *log;									/* [analy]   日志指针   */
    ngx_log_t                 new_log;

    ngx_connection_t        **files;
    ngx_connection_t         *free_connections;						//	指向空闲连接的链表
    ngx_uint_t                free_connection_n;					//	空闲连接的个数

    ngx_queue_t               reusable_connections_queue;			//	复用连接的队列

    ngx_array_t               listening;
    ngx_array_t               pathes;								/* [analy]   路径数组 （array of (ngx_path_t *)）*/					
    ngx_list_t                open_files;							/* [analy]   打开文件列表   */	
    ngx_list_t                shared_memory;						//	共享内存列表 array of ngx_shm_zone_t

    ngx_uint_t                connection_n;							/* [analy]   每个进程预先创建的connection数目(worker_connections指令指定) */
    ngx_uint_t                files_n;

    ngx_connection_t         *connections;							/* [analy]   连接池   */	
    ngx_event_t              *read_events;							/* [analy]   读事件   */	
    ngx_event_t              *write_events;							/* [analy]   写事件   */	

    ngx_cycle_t              *old_cycle;							/* [analy]	旧的cycle(old_cycle) */

    ngx_str_t                 conf_file;							/* [analy]	配置文件 */
    ngx_str_t                 conf_param;							/* [analy]	配置指令 */
    ngx_str_t                 conf_prefix;							//	配置文件前缀(工作目录)				"/usr/local/nginx/conf/"
    ngx_str_t                 prefix;								//	工作目录前缀，或命令行前缀"-p"设置	"/usr/local/nginx/"
    ngx_str_t                 lock_file;							/* [analy]	在init_conf时设置。使用连接互斥锁进行顺序的accept()系统调用默认是“logs/nginx.lock.accept” */
    ngx_str_t                 hostname;								/* [analy]	主机名 */
};


typedef struct {
     ngx_flag_t               daemon;
     ngx_flag_t               master;								//	指令master_process指定此字段，on = 1、off = 0 

     ngx_msec_t               timer_resolution;						//	指令"timer_resolution"设置的时间

     ngx_int_t                worker_processes;
     ngx_int_t                debug_points;

     ngx_int_t                rlimit_nofile;						//	此字段在worker进程初始化时设置到内核。指令worker_rlimit_nofile 进程能够打开的最多文件描述符数
     ngx_int_t                rlimit_sigpending;
     off_t                    rlimit_core;

     int                      priority;

     ngx_uint_t               cpu_affinity_n;
     u_long                  *cpu_affinity;

     char                    *username;								//	指令 "user" 设置的用户名
     ngx_uid_t                user;									//	uid
     ngx_gid_t                group;								//	gid

     ngx_str_t                working_directory;
     ngx_str_t                lock_file;							/* [analy]	指令lock_file指定锁文件名，未指定时使用默认“logs/nginx.lock” */

     ngx_str_t                pid;									/* [analy]	指令pid如果没有指定存放pid的文件路径则使用默认“logs/nginx.pid”路径 */
     ngx_str_t                oldpid;

     ngx_array_t              env;
     char                   **environment;

#if (NGX_THREADS)
     ngx_int_t                worker_threads;
     size_t                   thread_stack_size;
#endif

} ngx_core_conf_t;


typedef struct {
     ngx_pool_t              *pool;   /* pcre's malloc() pool */
} ngx_core_tls_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
u_long ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_quiet_mode;
#if (NGX_THREADS)
extern ngx_tls_key_t          ngx_core_tls_key;
#endif


#endif /* _NGX_CYCLE_H_INCLUDED_ */
