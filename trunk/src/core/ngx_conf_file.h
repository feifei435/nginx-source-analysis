
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CONF_FILE_H_INCLUDED_
#define _NGX_HTTP_CONF_FILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 *        AAAA  number of agruments
 *      FF      command flags
 *    TT        command type, i.e. HTTP "location" or "server" command
 */

#define NGX_CONF_NOARGS      0x00000001								/* [analy]   无参数	   		*/
#define NGX_CONF_TAKE1       0x00000002								/* [analy]   1个参数	   		*/
#define NGX_CONF_TAKE2       0x00000004								/* [analy]   2个参数	   		*/
#define NGX_CONF_TAKE3       0x00000008								/* [analy]   3个参数	   		*/
#define NGX_CONF_TAKE4       0x00000010								/* [analy]   4个参数	   		*/
#define NGX_CONF_TAKE5       0x00000020								/* [analy]   5个参数	   		*/
#define NGX_CONF_TAKE6       0x00000040								/* [analy]   6个参数	   		*/
#define NGX_CONF_TAKE7       0x00000080								/* [analy]   7个参数	   		*/

#define NGX_CONF_MAX_ARGS    8										/* [analy]   最大参数个数	*/

#define NGX_CONF_TAKE12      (NGX_CONF_TAKE1|NGX_CONF_TAKE2)		/* [analy]   有1个或2个参数  */
#define NGX_CONF_TAKE13      (NGX_CONF_TAKE1|NGX_CONF_TAKE3)		/* [analy]   有1个或3个参数  */

#define NGX_CONF_TAKE23      (NGX_CONF_TAKE2|NGX_CONF_TAKE3)		/* [analy]   有2个或3个参数  */

#define NGX_CONF_TAKE123     (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3)
#define NGX_CONF_TAKE1234    (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3   \
                              |NGX_CONF_TAKE4)

#define NGX_CONF_ARGS_NUMBER 0x000000ff
#define NGX_CONF_BLOCK       0x00000100								/* [analy]   标识该配置项为块类型值   i.e. "events" or "http"  */
#define NGX_CONF_FLAG        0x00000200								/* [analy]   标识该配置项为布尔类型值 i.e. "on" or "off"		 */
#define NGX_CONF_ANY         0x00000400
#define NGX_CONF_1MORE       0x00000800								/* [analy]   最多有一个参数		 */
#define NGX_CONF_2MORE       0x00001000								/* [analy]   最多有两个参数		 */
#define NGX_CONF_MULTI       0x00002000

#define NGX_DIRECT_CONF      0x00010000								/* [analy]   配置命令包含项指不包含二级模块指令 */			

#define NGX_MAIN_CONF        0x01000000								/* [analy]   指最顶层的指令		 */
#define NGX_ANY_CONF         0x0F000000								/* [analy]   i.e. include指令	 */	



#define NGX_CONF_UNSET       -1
#define NGX_CONF_UNSET_UINT  (ngx_uint_t) -1
#define NGX_CONF_UNSET_PTR   (void *) -1
#define NGX_CONF_UNSET_SIZE  (size_t) -1
#define NGX_CONF_UNSET_MSEC  (ngx_msec_t) -1


#define NGX_CONF_OK          NULL
#define NGX_CONF_ERROR       (void *) -1

#define NGX_CONF_BLOCK_START 1
#define NGX_CONF_BLOCK_DONE  2
#define NGX_CONF_FILE_DONE   3

#define NGX_CORE_MODULE      0x45524F43  /* "CORE" */
#define NGX_CONF_MODULE      0x464E4F43  /* "CONF" */


#define NGX_MAX_CONF_ERRSTR  1024


struct ngx_command_s {
    ngx_str_t             name;						/* [analy]   指令名称	   */		
    ngx_uint_t            type;						/* [analy]   type是标识符集，标识指令在配置文件中的合法位置和指令的参数个数.
													 				这是一个至少有32bit的无符号整形，前16bit用于标识位置，后16bit用于标识参数 */													 
    char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);		/* [analy]   函数执行解析并获取配置项值的操作 */
    ngx_uint_t            conf;						/* [analy]   字段conf被NGX_HTTP_MODULE类型模块所用，该字段指定当前配置项所在的大致位置 */
    ngx_uint_t            offset;					/* [analy]   解析出来的配置项值所存放的地址 */
    void                 *post;
};

#define ngx_null_command  { ngx_null_string, 0, NULL, 0, 0, NULL }


struct ngx_open_file_s {
    ngx_fd_t              fd;
    ngx_str_t             name;

    u_char               *buffer;
    u_char               *pos;
    u_char               *last;

#if 0
    /* e.g. append mode, error_log */
    ngx_uint_t            flags;
    /* e.g. reopen db file */
    ngx_uint_t          (*handler)(void *data, ngx_open_file_t *file);
    void                 *data;
#endif
};


#define NGX_MODULE_V1          0, 0, 0, 0, 0, 0, 1
#define NGX_MODULE_V1_PADDING  0, 0, 0, 0, 0, 0, 0, 0

struct ngx_module_s {
    ngx_uint_t            ctx_index;							/* [analy]	分类的模块计数器(本类型中的计数)   */
    ngx_uint_t            index;								/* [analy]	模块计数器   */
	
    ngx_uint_t            spare0;
    ngx_uint_t            spare1;
    ngx_uint_t            spare2;
    ngx_uint_t            spare3;

    ngx_uint_t            version;

    void                 *ctx;									/* [analy]	ctx是模块的上下文，不同种类的模块有不同的上下文   */
    ngx_command_t        *commands;								/* [analy]	commands 是模块的指令集，nginx的每个模块都可以实现一些自定义的指令，
																				这些指令写在配置文件的适当配置项中，每一个指令在源码中对应着一个 ngx_command_t结构的变量 */
   
	ngx_uint_t            type;

    ngx_int_t           (*init_master)(ngx_log_t *log);

    ngx_int_t           (*init_module)(ngx_cycle_t *cycle);

    ngx_int_t           (*init_process)(ngx_cycle_t *cycle);	/* [analy]	worker进程初始化时调用 */
    ngx_int_t           (*init_thread)(ngx_cycle_t *cycle);
    void                (*exit_thread)(ngx_cycle_t *cycle);
    void                (*exit_process)(ngx_cycle_t *cycle);

    void                (*exit_master)(ngx_cycle_t *cycle);

    uintptr_t             spare_hook0;
    uintptr_t             spare_hook1;
    uintptr_t             spare_hook2;
    uintptr_t             spare_hook3;
    uintptr_t             spare_hook4;
    uintptr_t             spare_hook5;
    uintptr_t             spare_hook6;
    uintptr_t             spare_hook7;
};


typedef struct {
    ngx_str_t             name;
    void               *(*create_conf)(ngx_cycle_t *cycle);					/* [analy]	创建并初始化模块配置结构变量   */
    char               *(*init_conf)(ngx_cycle_t *cycle, void *conf);		/* [analy]	设置配置结构变量   */
} ngx_core_module_t;


typedef struct {
    ngx_file_t            file;
    ngx_buf_t            *buffer;
    ngx_uint_t            line;
} ngx_conf_file_t;


typedef char *(*ngx_conf_handler_pt)(ngx_conf_t *cf,
    ngx_command_t *dummy, void *conf);


/*
 *	[analy] 该结构保存了解析配置文件所需要的一些域
 */
struct ngx_conf_s {
    char                 *name;				/* [analy] 当前解析到的命令名 */
    ngx_array_t          *args;				// 当前命令的所有参数(array of ngx_str_t)

    ngx_cycle_t          *cycle;			/* [analy] 当前使用的cycle */
    ngx_pool_t           *pool;				/* [analy] 当前使用的pool */
    ngx_pool_t           *temp_pool;		/* [analy] 这个pool将会在配置解析完毕后释放 */
    ngx_conf_file_t      *conf_file;		/* [analy] 要解析的配置文件 */
    ngx_log_t            *log;				/* [analy] 配置Log */

    void                 *ctx;				/* [analy] 主要为了提供模块的层次化(后续会详细介绍) */
    ngx_uint_t            module_type;		/* [analy] 模块类型 */
    ngx_uint_t            cmd_type;			/* [analy] 命令类型 */

    ngx_conf_handler_pt   handler;			/* [analy] 模块定义的handler */
    char                 *handler_conf;		/* [analy] 自定义的handler */
};


typedef char *(*ngx_conf_post_handler_pt) (ngx_conf_t *cf,
    void *data, void *conf);

typedef struct {
    ngx_conf_post_handler_pt  post_handler;
} ngx_conf_post_t;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    char                     *old_name;
    char                     *new_name;
} ngx_conf_deprecated_t;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    ngx_int_t                 low;
    ngx_int_t                 high;
} ngx_conf_num_bounds_t;


typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                value;
} ngx_conf_enum_t;


#define NGX_CONF_BITMASK_SET  1

typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                mask;
} ngx_conf_bitmask_t;



char * ngx_conf_deprecated(ngx_conf_t *cf, void *post, void *data);
char *ngx_conf_check_num_bounds(ngx_conf_t *cf, void *post, void *data);


#define ngx_get_conf(conf_ctx, module)  conf_ctx[module.index]



#define ngx_conf_init_value(conf, default)                                   \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }

#define ngx_conf_init_ptr_value(conf, default)                               \
    if (conf == NGX_CONF_UNSET_PTR) {                                        \
        conf = default;                                                      \
    }

#define ngx_conf_init_uint_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_UINT) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_init_size_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_SIZE) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_init_msec_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_MSEC) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_merge_value(conf, prev, default)                            \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_ptr_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET_PTR) {                                        \
        conf = (prev == NGX_CONF_UNSET_PTR) ? default : prev;                \
    }

#define ngx_conf_merge_uint_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_UINT) {                                       \
        conf = (prev == NGX_CONF_UNSET_UINT) ? default : prev;               \
    }

#define ngx_conf_merge_msec_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_MSEC) {                                       \
        conf = (prev == NGX_CONF_UNSET_MSEC) ? default : prev;               \
    }

#define ngx_conf_merge_sec_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

/*  
 * 意思很明确，如果下层的某个变量没有配置，那么就用上层(若有设置的话)的，因为我们在使用srv_conf或者 
 * loc_conf的时候一般都是要用到底层的，也就是具体请求对应的location的配置，很多srv_conf的配置是需要传递下来 
 * 供下层使用的，(main_conf底层跟上层都是共享的) 
 */ 
#define ngx_conf_merge_size_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_SIZE) {                                       \
        conf = (prev == NGX_CONF_UNSET_SIZE) ? default : prev;               \
    }

#define ngx_conf_merge_off_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_str_value(conf, prev, default)                        \
    if (conf.data == NULL) {                                                 \
        if (prev.data) {                                                     \
            conf.len = prev.len;                                             \
            conf.data = prev.data;                                           \
        } else {                                                             \
            conf.len = sizeof(default) - 1;                                  \
            conf.data = (u_char *) default;                                  \
        }                                                                    \
    }

#define ngx_conf_merge_bufs_value(conf, prev, default_num, default_size)     \
    if (conf.num == 0) {                                                     \
        if (prev.num) {                                                      \
            conf.num = prev.num;                                             \
            conf.size = prev.size;                                           \
        } else {                                                             \
            conf.num = default_num;                                          \
            conf.size = default_size;                                        \
        }                                                                    \
    }

#define ngx_conf_merge_bitmask_value(conf, prev, default)                    \
    if (conf == 0) {                                                         \
        conf = (prev == 0) ? default : prev;                                 \
    }


char *ngx_conf_param(ngx_conf_t *cf);
char *ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename);


ngx_int_t ngx_conf_full_name(ngx_cycle_t *cycle, ngx_str_t *name,
    ngx_uint_t conf_prefix);
ngx_open_file_t *ngx_conf_open_file(ngx_cycle_t *cycle, ngx_str_t *name);
void ngx_cdecl ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf,
    ngx_err_t err, const char *fmt, ...);


char *ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_str_array_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_conf_set_keyval_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_off_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_sec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_enum_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_bitmask_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


extern ngx_uint_t     ngx_max_module;
extern ngx_module_t  *ngx_modules[];


#endif /* _NGX_HTTP_CONF_FILE_H_INCLUDED_ */
