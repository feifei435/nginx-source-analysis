
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define DEFAULT_CONNECTIONS  512


extern ngx_module_t ngx_kqueue_module;
extern ngx_module_t ngx_eventport_module;
extern ngx_module_t ngx_devpoll_module;
extern ngx_module_t ngx_epoll_module;
extern ngx_module_t ngx_rtsig_module;
extern ngx_module_t ngx_select_module;


static ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle);
static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_event_create_conf(ngx_cycle_t *cycle);
static char *ngx_event_init_conf(ngx_cycle_t *cycle, void *conf);


static ngx_uint_t     ngx_timer_resolution;					//	timer_resolutionָ��ָ����ʱ��; ���������������gettimeofday()ϵͳ���õ�ʱ�䣬Ĭ�������gettimeofday()�����ж�������ɺ�Żᱻ���ã�kevent(), epoll, /dev/poll, select(), poll()��
															//	�������Ҫһ���Ƚ�׼ȷ��ʱ������¼$upstream_response_time����$msec����������ܻ��õ�timer_resolution
sig_atomic_t          ngx_event_timer_alarm;				//	ָ��"timer_resolution"���ú�ÿ��ngx_timer_resolution��������һ��SIGALRM�ź�
	
static ngx_uint_t     ngx_event_max_module;

ngx_uint_t            ngx_event_flags;
ngx_event_actions_t   ngx_event_actions;					/* [analy]	ָ���IO����ģ���actions�ṹ�壬��IO�¼����ֲ����ķ�װ	*/


static ngx_atomic_t   connection_counter = 1;
ngx_atomic_t         *ngx_connection_counter = &connection_counter;


ngx_atomic_t         *ngx_accept_mutex_ptr;
ngx_shmtx_t           ngx_accept_mutex;					//	"nginx.lock.accept"���ļ���
ngx_uint_t            ngx_use_accept_mutex;				//	��ʾ�Ƿ���Ҫͨ����accept�����������Ⱥ���⣬ �����ļ��д�accept_mutex��1���Ѵ� (ngx_event_process_init()����������)
ngx_uint_t            ngx_accept_events;				//	ò��ûʲô��
ngx_uint_t            ngx_accept_mutex_held;			//	�Ƿ�������, ������ʱ=1�������෴(ngx_trylock_accept_mutex()����������)
ngx_msec_t            ngx_accept_mutex_delay;			//	ָ�� "accept_mutex_delay" ����
ngx_int_t             ngx_accept_disabled;
ngx_file_t            ngx_accept_mutex_lock_file;


#if (NGX_STAT_STUB)

ngx_atomic_t   ngx_stat_accepted0;
ngx_atomic_t  *ngx_stat_accepted = &ngx_stat_accepted0;
ngx_atomic_t   ngx_stat_handled0;
ngx_atomic_t  *ngx_stat_handled = &ngx_stat_handled0;
ngx_atomic_t   ngx_stat_requests0;
ngx_atomic_t  *ngx_stat_requests = &ngx_stat_requests0;
ngx_atomic_t   ngx_stat_active0;
ngx_atomic_t  *ngx_stat_active = &ngx_stat_active0;
ngx_atomic_t   ngx_stat_reading0;
ngx_atomic_t  *ngx_stat_reading = &ngx_stat_reading0;
ngx_atomic_t   ngx_stat_writing0;
ngx_atomic_t  *ngx_stat_writing = &ngx_stat_writing0;

#endif



static ngx_command_t  ngx_events_commands[] = {

    { ngx_string("events"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_events_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_events_module_ctx = {
    ngx_string("events"),
    NULL,
    NULL
};


ngx_module_t  ngx_events_module = {
    NGX_MODULE_V1,
    &ngx_events_module_ctx,                /* module context */
    ngx_events_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  event_core_name = ngx_string("event_core");


static ngx_command_t  ngx_event_core_commands[] = {

    { ngx_string("worker_connections"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_connections,
      0,
      0,
      NULL },

    { ngx_string("connections"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_connections,
      0,
      0,
      NULL },

    { ngx_string("use"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_use,
      0,
      0,
      NULL },

    { ngx_string("multi_accept"),
      NGX_EVENT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, multi_accept),
      NULL },

    { ngx_string("accept_mutex"),
      NGX_EVENT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, accept_mutex),
      NULL },

    { ngx_string("accept_mutex_delay"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_event_conf_t, accept_mutex_delay),
      NULL },

    { ngx_string("debug_connection"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_debug_connection,
      0,
      0,
      NULL },

      ngx_null_command
};


ngx_event_module_t  ngx_event_core_module_ctx = {
    &event_core_name,
    ngx_event_create_conf,                 /* create configuration */
    ngx_event_init_conf,                   /* init configuration */

    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


ngx_module_t  ngx_event_core_module = {
    NGX_MODULE_V1,
    &ngx_event_core_module_ctx,            /* module context */
    ngx_event_core_commands,               /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    ngx_event_module_init,                 /* init module */
    ngx_event_process_init,                /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
	������Ժ�ngx_accept_mutex_held��������Ϊtrue, ���ڵ���ngx_process_epoll_event��ʱ��ѱ�־λ���ó� NGX_POST_EVENTS�����ʹepoll�ڽ��ܵ��¼���ʱ��
	��ʱ�����������Ƿŵ�һ����������ʱ�����������ȵ��ͷ���accept��֮��Ŵ�����Щ�¼������Ч�ʡ� 
*/
void
ngx_process_events_and_timers(ngx_cycle_t *cycle)
{
    ngx_uint_t  flags;
    ngx_msec_t  timer, delta;

    if (ngx_timer_resolution) {						//	ʹ���� timer_resolution ָ�epoll_wait�������ȴ�
        timer = NGX_TIMER_INFINITE;
        flags = 0;

    } else {
        timer = ngx_event_find_timer();
        flags = NGX_UPDATE_TIME;

#if (NGX_THREADS)

        if (timer == NGX_TIMER_INFINITE || timer > 500) {
            timer = 500;
        }

#endif
    }

	/* 
	 *	[analy] ϵͳʹ��accpte_mutex���������Ⱥ���⣬��listen->fd���н���accept����ʱ 
	 */
    if (ngx_use_accept_mutex) {			
		
		/* 
		 *	[analy] 	ngx_accept_disabled��ʾ��ʱ�����ɣ�û��Ҫ�ٴ����������ˣ�������nginx.conf����������ÿһ��nginx worker�����ܹ������������������
		 *				���ﵽ�������7/8ʱ��ngx_accept_disabledΪ����˵����nginx worker���̷ǳ���æ��������ȥ���������ӣ���Ҳ�Ǹ��򵥵ĸ��ؾ��� 
		 */
        if (ngx_accept_disabled > 0) {
            ngx_accept_disabled--;

        } else {

			/* 
			 *	�õ�accept����flags=NGX_POST_EVENTS�� ���ʹ���epoll�ڽ��յ��¼���ʱ�� accept�¼���ʱ��������
			 *			���Ƿŵ�һ����������ʱ��������(ngx_posted_accept_events������)���ȵ��ͷ���accept��֮��Ŵ�����Щ�¼������Ч��	
			 *			epollin|epollout�¼����ŵ�ngx_posted_events������  
			 */
            if (ngx_trylock_accept_mutex(cycle) == NGX_ERROR) {		
                return;
            }

            if (ngx_accept_mutex_held) {					//	�����������ñ��NGX_POST_EVENTS
                flags |= NGX_POST_EVENTS;

            } else {										
				
				/* 
				 *	�ò�������Ҳ�Ͳ��ᴦ�������ľ�������timerʵ���Ǵ���epoll_wait�ĳ�ʱʱ�䣬
				 *	�޸�Ϊ���ngx_accept_mutex_delay��ζ��epoll_wait���̵ĳ�ʱ���أ����������ӳ�ʱ��û�еõ�����
				 */
                if (timer == NGX_TIMER_INFINITE
                    || timer > ngx_accept_mutex_delay)
                {
                    timer = ngx_accept_mutex_delay;
                }
            }
        }
    }

    delta = ngx_current_msec;

    (void) ngx_process_events(cycle, timer, flags);				//	��ʱ����ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)

    delta = ngx_current_msec - delta;							//	����ngx_epoll_process_events()�������������ĺ�����

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "timer delta: %M", delta);


	//	���ngx_posted_accept_events���������ݣ��Ϳ�ʼaccept����������
    if (ngx_posted_accept_events) {
        ngx_event_process_posted(cycle, &ngx_posted_accept_events);
    }

	/*	�������accept�����������ͷ�	
		���⣺Ϊʲô��ʱ�ͷ����������ٴ���accept֮ǰ�ͷ��أ�
		�²⣺�����accept֮ǰ�ͷţ��������̻����accpet��������fd���¼���������ʱ�ӳٴ�����accept�¼�����������������
	*/
    if (ngx_accept_mutex_held) {
        ngx_shmtx_unlock(&ngx_accept_mutex);
    }

	/* ���ҳ�ʱ���¼�����ɾ�����ڵ���ע���handler */
    if (delta) {
        ngx_event_expire_timers();
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "posted events %p", ngx_posted_events);


	//	���ngx_posted_events���������ݣ���ʼ��������������д�¼�
    if (ngx_posted_events) {
        if (ngx_threaded) {
            ngx_wakeup_worker_thread(cycle);

        } else {
            ngx_event_process_posted(cycle, &ngx_posted_events);
        }
    }
}

/* 
 *	[analy]	������¼���epoll�¼����������У����ݴ���ģʽ�в�ͨ�Ĵ�����ʽ��
 */
ngx_int_t
ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags)
{
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {						/* [analy]	ʹ��edge triggered */

        /* kqueue, epoll */

        if (!rev->active && !rev->ready) {								//	�����¼����ڷǻ�Ծ״̬ʱ(��û�б����ӵ�epoll�¼���ض�����ʱ)�� rev->ready�Ǵ�����û�ж��¼�����
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT)		/* [analy]	����ngx_epoll_add_event()�� ��ʹ��epollʱ����NGX_CLEAR_EVENT������� EPOLLET */
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {					/* [analy]	ʹ��level triggered */

        /* select, poll, /dev/poll */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->active && (rev->ready || (flags & NGX_CLOSE_EVENT))) {
            if (ngx_del_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT | flags)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

    } else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->oneshot && !rev->ready) {
            if (ngx_del_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* aio, iocp, rtsig */

    return NGX_OK;
}

/* 
 *	[analy]	��д�¼����ӵ��¼�����������
 *			���� lowat: �������0�������÷��ͻ������ĵͳ���ֵ
 */
ngx_int_t
ngx_handle_write_event(ngx_event_t *wev, size_t lowat)
{
    ngx_connection_t  *c;

	
    if (lowat) {
			
		//	���÷��ͻ������ĵͳ���ֵ

        c = wev->data;

        if (ngx_send_lowat(c, lowat) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
	
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {				//	ʹ��edge triggered ģʽ

        /* kqueue, epoll */
		
		//	���¼�δ����epoll�¼�������ʱ��������д�¼���
        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT,
                              NGX_CLEAR_EVENT | (lowat ? NGX_LOWAT_EVENT : 0))			//	NGX_CLEAR_EVENT = EPOLLET
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {			//	ʹ��level triggerredģʽ

        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->active && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

    } else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->oneshot && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* aio, iocp, rtsig */

    return NGX_OK;
}


static ngx_int_t
ngx_event_module_init(ngx_cycle_t *cycle)
{
    void              ***cf;
    u_char              *shared;
    size_t               size, cl;
    ngx_shm_t            shm;
    ngx_time_t          *tp;
    ngx_core_conf_t     *ccf;
    ngx_event_conf_t    *ecf;

    cf = ngx_get_conf(cycle->conf_ctx, ngx_events_module);

    if (cf == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "no \"events\" section in configuration");
        return NGX_ERROR;
    }

    ecf = (*cf)[ngx_event_core_module.ctx_index];

    if (!ngx_test_config && ngx_process <= NGX_PROCESS_MASTER) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "using the \"%s\" event method", ecf->name);
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    ngx_timer_resolution = ccf->timer_resolution;

#if !(NGX_WIN32)
    {
    ngx_int_t      limit;
    struct rlimit  rlmt;

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {				/* [analy]	��ȡ�����ܴ򿪵�����ļ������ں�Ĭ����1024 */
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "getrlimit(RLIMIT_NOFILE) failed, ignored");

    } else {													
			
		/* [analy]	1. ��worker_connectionsָ������������ > ���̿��Դ򿪵��ļ����� ���� ָ��worker_rlimit_nofileû����ʾָ��
					2. ��worker_connectionsָ������������ > ָ��worker_rlimit_nofileָ���Ĵ��ļ��� 
		*/
        if (ecf->connections > (ngx_uint_t) rlmt.rlim_cur
            && (ccf->rlimit_nofile == NGX_CONF_UNSET
                || ecf->connections > (ngx_uint_t) ccf->rlimit_nofile))
        {
            limit = (ccf->rlimit_nofile == NGX_CONF_UNSET) ?
                         (ngx_int_t) rlmt.rlim_cur : ccf->rlimit_nofile;

            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "%ui worker_connections are more than "
                          "open file resource limit: %i",
                          ecf->connections, limit);
        }
    }
    }
#endif /* !(NGX_WIN32) */


    if (ccf->master == 0) {				/* [analy]	�����̹���ģʽ�������͵���ʱʹ�ã�master_process = off */
        return NGX_OK;
    }

    if (ngx_accept_mutex_ptr) {
        return NGX_OK;
    }


    /* cl should be equal or bigger than cache line size */

    cl = 128;

    size = cl            /* ngx_accept_mutex */
           + cl          /* ngx_connection_counter */
           + cl;         /* ngx_temp_number */

#if (NGX_STAT_STUB)

    size += cl           /* ngx_stat_accepted */
           + cl          /* ngx_stat_handled */
           + cl          /* ngx_stat_requests */
           + cl          /* ngx_stat_active */
           + cl          /* ngx_stat_reading */
           + cl;         /* ngx_stat_writing */

#endif

    shm.size = size;
    shm.name.len = sizeof("nginx_shared_zone");
    shm.name.data = (u_char *) "nginx_shared_zone";
    shm.log = cycle->log;

    if (ngx_shm_alloc(&shm) != NGX_OK) {
        return NGX_ERROR;
    }

    shared = shm.addr;

    ngx_accept_mutex_ptr = (ngx_atomic_t *) shared;
    ngx_accept_mutex.spin = (ngx_uint_t) -1;

	/* ����ngx_accept_mutex="nginx.lock.accept", cycle->lock_file��unlink����Ŀ¼���Ѿ����Ƴ���
				�������ڴ����е�����close()ʱ�Żᱻ����ɾ�� 
	*/
    if (ngx_shmtx_create(&ngx_accept_mutex, (ngx_shmtx_sh_t *) shared,
                         cycle->lock_file.data)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_connection_counter = (ngx_atomic_t *) (shared + 1 * cl);

    (void) ngx_atomic_cmp_set(ngx_connection_counter, 0, 1);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "counter: %p, %d",
                   ngx_connection_counter, *ngx_connection_counter);

    ngx_temp_number = (ngx_atomic_t *) (shared + 2 * cl);

    tp = ngx_timeofday();

    ngx_random_number = (tp->msec << 16) + ngx_pid;

#if (NGX_STAT_STUB)

    ngx_stat_accepted = (ngx_atomic_t *) (shared + 3 * cl);
    ngx_stat_handled = (ngx_atomic_t *) (shared + 4 * cl);
    ngx_stat_requests = (ngx_atomic_t *) (shared + 5 * cl);
    ngx_stat_active = (ngx_atomic_t *) (shared + 6 * cl);
    ngx_stat_reading = (ngx_atomic_t *) (shared + 7 * cl);
    ngx_stat_writing = (ngx_atomic_t *) (shared + 8 * cl);

#endif

    return NGX_OK;
}


#if !(NGX_WIN32)

void
ngx_timer_signal_handler(int signo)
{
    ngx_event_timer_alarm = 1;

#if 1
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0, "timer signal");
#endif
}

#endif


static ngx_int_t
ngx_event_process_init(ngx_cycle_t *cycle)
{
    ngx_uint_t           m, i;
    ngx_event_t         *rev, *wev;
    ngx_listening_t     *ls;
    ngx_connection_t    *c, *next, *old;
    ngx_core_conf_t     *ccf;
    ngx_event_conf_t    *ecf;
    ngx_event_module_t  *module;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

	/* [analy]  ngx_use_accept_mutex��ʾ�Ƿ���Ҫͨ����accept�����������Ⱥ���⡣
					��nginx worker������>1ʱ�������ļ��д�accept_mutexʱ�������־��Ϊ1 
	*/
    if (ccf->master && ccf->worker_processes > 1 && ecf->accept_mutex) {
        ngx_use_accept_mutex = 1;
        ngx_accept_mutex_held = 0;
        ngx_accept_mutex_delay = ecf->accept_mutex_delay;

    } else {
        ngx_use_accept_mutex = 0;
    }

#if (NGX_THREADS)
    ngx_posted_events_mutex = ngx_mutex_init(cycle->log, 0);
    if (ngx_posted_events_mutex == NULL) {
        return NGX_ERROR;
    }
#endif

	/* [analy]	??????????? */
    if (ngx_event_timer_init(cycle->log) == NGX_ERROR) {
        return NGX_ERROR;
    }

	/* [analy]	�����¼�����ģ��(epoll)��ʼ������ */
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        if (ngx_modules[m]->ctx_index != ecf->use) {
            continue;
        }

		/* [analy]
			����Nginxʵ���˺ܶ���¼�ģ�飬���磺epoll��poll��select, kqueue,aio 
			����Щģ��λ��src/event/modulesĿ¼�У��ȵȣ�����Nginx���¼�ģ����� 
			��һ����󣬷����ڲ�ͬ��ϵͳ��ʹ�ò�ͬ���¼�ģ�ͣ�Ҳ������չ�µ��¼� 
			ģ��
			�˴���init�ص�����ʵ���ǵ�����ngx_epoll_init������module->actions�ṹ 
			��װ��epoll�����нӿں�����Nginx����ͨ��actions�ṹ��epollע�ᵽ�¼� 
			������С�actions��������ngx_event_actions_t
		*/
        module = ngx_modules[m]->ctx;

        if (module->actions.init(cycle, ngx_timer_resolution) != NGX_OK) {
            /* fatal */
            exit(2);
        }

        break;
    }

#if !(NGX_WIN32)

	/* 
	 *	timer_resolutionָ��ָ����ʱ�䣬����δָ��NGX_USE_TIMER_EVENT���ʱ�� 
	 *			���� timer_resolution ָ��ָ����ʱ������һ����ʱ��
	 */
    if (ngx_timer_resolution && !(ngx_event_flags & NGX_USE_TIMER_EVENT)) {
        struct sigaction  sa;
        struct itimerval  itv;

        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = ngx_timer_signal_handler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGALRM, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "sigaction(SIGALRM) failed");
            return NGX_ERROR;
        }

        itv.it_interval.tv_sec = ngx_timer_resolution / 1000;
        itv.it_interval.tv_usec = (ngx_timer_resolution % 1000) * 1000;
        itv.it_value.tv_sec = ngx_timer_resolution / 1000;
        itv.it_value.tv_usec = (ngx_timer_resolution % 1000 ) * 1000;

        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setitimer() failed");
        }
    }

    if (ngx_event_flags & NGX_USE_FD_EVENT) {					/* [analy]	epollģ�鲻ʹ�� */
        struct rlimit  rlmt;	

        if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "getrlimit(RLIMIT_NOFILE) failed");
            return NGX_ERROR;
        }

        cycle->files_n = (ngx_uint_t) rlmt.rlim_cur;

        cycle->files = ngx_calloc(sizeof(ngx_connection_t *) * cycle->files_n,
                                  cycle->log);
        if (cycle->files == NULL) {
            return NGX_ERROR;
        }
    }

#endif

	/* [analy]	Ϊ���ӳ�����ռ䣬���ڴ˴���worker���̳�ʼ��ʱ���еģ�����
					ÿ��worker����ӵ��һ���Լ���connections���ӳ�	
					��������worker_connectionsָ��ָ���ĸ������� */
    cycle->connections =
        ngx_alloc(sizeof(ngx_connection_t) * cycle->connection_n, cycle->log);
    if (cycle->connections == NULL) {
        return NGX_ERROR;
    }

    c = cycle->connections;
	
	/* [analy]	Ϊ���¼���������ռ� */
    cycle->read_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,
                                   cycle->log);
    if (cycle->read_events == NULL) {
        return NGX_ERROR;
    }

    rev = cycle->read_events;
    for (i = 0; i < cycle->connection_n; i++) {
        rev[i].closed = 1;
        rev[i].instance = 1;
#if (NGX_THREADS)
        rev[i].lock = &c[i].lock;
        rev[i].own_lock = &c[i].lock;
#endif
    }

	/* [analy]	Ϊд�¼���������ռ� */
    cycle->write_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,
                                    cycle->log);
    if (cycle->write_events == NULL) {
        return NGX_ERROR;
    }

    wev = cycle->write_events;
    for (i = 0; i < cycle->connection_n; i++) {
        wev[i].closed = 1;
#if (NGX_THREADS)
        wev[i].lock = &c[i].lock;
        wev[i].own_lock = &c[i].lock;
#endif
    }

	/* [analy]	��ʼ��connections����
					data�ֶ�ָ����һ��Ԫ��
					read�¼�ָ��ָ��read_events��Ӧ�±��Ԫ��
					write�¼�ָ��ָ��write_events��Ӧ�±��Ԫ��
					fd��ʼ��-1
	*/

    i = cycle->connection_n;
    next = NULL;

    do {
        i--;

        c[i].data = next;
        c[i].read = &cycle->read_events[i];			/* [analy]	�����ӳ���connections��read�¼���read_events�����еĶ�Ӧ�±��Ԫ�ع��� */
        c[i].write = &cycle->write_events[i];		/* [analy]	�����ӳ���connections��write�¼���write_events�����ж�Ӧ�±�Ԫ�ع��� */
        c[i].fd = (ngx_socket_t) -1;

        next = &c[i];

#if (NGX_THREADS)
        c[i].lock = 0;
#endif
    } while (i);

	/* [analy]	��ʼ��free_connections�������ӳغͿ������Ӹ���;ָ��connections���ӳ��׵�ַ */
    cycle->free_connections = next;
    cycle->free_connection_n = cycle->connection_n;

	/* [analy]	Ϊÿһ���׽ӿڷ���һ�����е����� */
    /* for each listening socket */
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ngx_get_connection(ls[i].fd, cycle->log);

        if (c == NULL) {
            return NGX_ERROR;
        }

        c->log = &ls[i].log;

        c->listening = &ls[i];					/* [analy]	connection��listeningָ��ָ��cycle->listening[n] */	
        ls[i].connection = c;					/* [analy]	cycle->listening[n]->connectionָ��ָ��������Ŀ���connection */	
			
        rev = c->read;

        rev->log = c->log;
        rev->accept = 1;						//	���ü����׽��ֱ�ʶ

#if (NGX_HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = ls[i].deferred_accept;
#endif

        if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)) {
            if (ls[i].previous) {

                /*
                 * delete the old accept events that were bound to
                 * the old cycle read events array
                 */

                old = ls[i].previous->connection;

                if (ngx_del_event(old->read, NGX_READ_EVENT, NGX_CLOSE_EVENT)
                    == NGX_ERROR)
                {
                    return NGX_ERROR;
                }

                old->fd = (ngx_socket_t) -1;
            }
        }

#if (NGX_WIN32)

        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            ngx_iocp_conf_t  *iocpcf;

            rev->handler = ngx_event_acceptex;

            if (ngx_use_accept_mutex) {
                continue;
            }

            if (ngx_add_event(rev, 0, NGX_IOCP_ACCEPT) == NGX_ERROR) {
                return NGX_ERROR;
            }

            ls[i].log.handler = ngx_acceptex_log_error;

            iocpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);
            if (ngx_event_post_acceptex(&ls[i], iocpcf->post_acceptex)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

        } else {
            rev->handler = ngx_event_accept;

            if (ngx_use_accept_mutex) {
                continue;
            }

            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

#else

        rev->handler = ngx_event_accept;			/* [analy]	����accpet�ص��������� */	

        if (ngx_use_accept_mutex) {
            continue;
        }

        if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
            if (ngx_add_conn(c) == NGX_ERROR) {
                return NGX_ERROR;
            }

        } else {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {			/* [analy]	��event�ͽ�epoll������ */
                return NGX_ERROR;
            }
        }

#endif

    }

    return NGX_OK;
}

/*
 *	[analy]	����socket���ͻ������ͳ�����
 */
ngx_int_t
ngx_send_lowat(ngx_connection_t *c, size_t lowat)
{
    int  sndlowat;

#if (NGX_HAVE_LOWAT_EVENT)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        c->write->available = lowat;
        return NGX_OK;
    }

#endif

    if (lowat == 0 || c->sndlowat) {		//	���÷��ͻ�������С���Ϊ0�����Ѿ����ù�����ֱ�ӷ��ء�
        return NGX_OK;
    }

    sndlowat = (int) lowat;

    if (setsockopt(c->fd, SOL_SOCKET, SO_SNDLOWAT,
                   (const void *) &sndlowat, sizeof(int))
        == -1)
    {
        ngx_connection_error(c, ngx_socket_errno,
                             "setsockopt(SO_SNDLOWAT) failed");
        return NGX_ERROR;
    }

    c->sndlowat = 1;

    return NGX_OK;
}


static char *
ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                 *rv;
    void               ***ctx;
    ngx_uint_t            i;
    ngx_conf_t            pcf;
    ngx_event_module_t   *m;

    /* count the number of the event modules and set up their indices */

    ngx_event_max_module = 0;
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        ngx_modules[i]->ctx_index = ngx_event_max_module++;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(void *));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *ctx = ngx_pcalloc(cf->pool, ngx_event_max_module * sizeof(void *));
    if (*ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(void **) conf = ctx;

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = ngx_modules[i]->ctx;

        if (m->create_conf) {
            (*ctx)[ngx_modules[i]->ctx_index] = m->create_conf(cf->cycle);
            if ((*ctx)[ngx_modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_EVENT_MODULE;
    cf->cmd_type = NGX_EVENT_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK)
        return rv;

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = ngx_modules[i]->ctx;

        if (m->init_conf) {
            rv = m->init_conf(cf->cycle, (*ctx)[ngx_modules[i]->ctx_index]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    ngx_str_t  *value;

    if (ecf->connections != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(cmd->name.data, "connections") == 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "the \"connections\" directive is deprecated, "
                           "use the \"worker_connections\" directive instead");
    }

    value = cf->args->elts;
    ecf->connections = ngx_atoi(value[1].data, value[1].len);
    if (ecf->connections == (ngx_uint_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%V\"", &value[1]);

        return NGX_CONF_ERROR;
    }

    cf->cycle->connection_n = ecf->connections;

    return NGX_CONF_OK;
}


static char *
ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    ngx_int_t             m;
    ngx_str_t            *value;
    ngx_event_conf_t     *old_ecf;
    ngx_event_module_t   *module;

    if (ecf->use != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->cycle->old_cycle->conf_ctx) {
        old_ecf = ngx_event_get_conf(cf->cycle->old_cycle->conf_ctx,
                                     ngx_event_core_module);
    } else {
        old_ecf = NULL;
    }


    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        if (module->name->len == value[1].len) {
            if (ngx_strcmp(module->name->data, value[1].data) == 0) {
                ecf->use = ngx_modules[m]->ctx_index;
                ecf->name = module->name->data;

                if (ngx_process == NGX_PROCESS_SINGLE
                    && old_ecf
                    && old_ecf->use != ecf->use)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "when the server runs without a master process "
                               "the \"%V\" event type must be the same as "
                               "in previous configuration - \"%s\" "
                               "and it cannot be changed on the fly, "
                               "to change it you need to stop server "
                               "and start it again",
                               &value[1], old_ecf->name);

                    return NGX_CONF_ERROR;
                }

                return NGX_CONF_OK;
            }
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid event type \"%V\"", &value[1]);

    return NGX_CONF_ERROR;
}


static char *
ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_DEBUG)
    ngx_event_conf_t  *ecf = conf;

    ngx_int_t           rc;
    ngx_str_t          *value;
    ngx_event_debug_t  *dc;
    struct hostent     *h;
    ngx_cidr_t          cidr;

    value = cf->args->elts;

    dc = ngx_array_push(&ecf->debug_connection);
    if (dc == NULL) {
        return NGX_CONF_ERROR;
    }

    rc = ngx_ptocidr(&value[1], &cidr);

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", &value[1]);
        rc = NGX_OK;
    }

    if (rc == NGX_OK) {

        /* AF_INET only */

        if (cidr.family != AF_INET) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"debug_connection\" supports IPv4 only");
            return NGX_CONF_ERROR;
        }

        dc->mask = cidr.u.in.mask;
        dc->addr = cidr.u.in.addr;

        return NGX_CONF_OK;
    }

    h = gethostbyname((char *) value[1].data);

    if (h == NULL || h->h_addr_list[0] == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "host \"%s\" not found", value[1].data);
        return NGX_CONF_ERROR;
    }

    dc->mask = 0xffffffff;
    dc->addr = *(in_addr_t *)(h->h_addr_list[0]);

#else

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"debug_connection\" is ignored, you need to rebuild "
                       "nginx using --with-debug option to enable it");

#endif

    return NGX_CONF_OK;
}


static void *
ngx_event_create_conf(ngx_cycle_t *cycle)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_palloc(cycle->pool, sizeof(ngx_event_conf_t));
    if (ecf == NULL) {
        return NULL;
    }

    ecf->connections = NGX_CONF_UNSET_UINT;
    ecf->use = NGX_CONF_UNSET_UINT;
    ecf->multi_accept = NGX_CONF_UNSET;
    ecf->accept_mutex = NGX_CONF_UNSET;
    ecf->accept_mutex_delay = NGX_CONF_UNSET_MSEC;
    ecf->name = (void *) NGX_CONF_UNSET;

#if (NGX_DEBUG)

    if (ngx_array_init(&ecf->debug_connection, cycle->pool, 4,
                       sizeof(ngx_event_debug_t)) == NGX_ERROR)
    {
        return NULL;
    }

#endif

    return ecf;
}


static char *
ngx_event_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

#if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)
    int                  fd;
#endif
#if (NGX_HAVE_RTSIG)
    ngx_uint_t           rtsig;
    ngx_core_conf_t     *ccf;
#endif
    ngx_int_t            i;
    ngx_module_t        *module;
    ngx_event_module_t  *event_module;

    module = NULL;

#if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)

    fd = epoll_create(100);

    if (fd != -1) {
        close(fd);
        module = &ngx_epoll_module;

    } else if (ngx_errno != NGX_ENOSYS) {
        module = &ngx_epoll_module;
    }

#endif

#if (NGX_HAVE_RTSIG)

    if (module == NULL) {
        module = &ngx_rtsig_module;
        rtsig = 1;

    } else {
        rtsig = 0;
    }

#endif

#if (NGX_HAVE_DEVPOLL)

    module = &ngx_devpoll_module;

#endif

#if (NGX_HAVE_KQUEUE)

    module = &ngx_kqueue_module;

#endif

#if (NGX_HAVE_SELECT)

    if (module == NULL) {
        module = &ngx_select_module;
    }

#endif

	
	/* [analy]	��ȡevent�����¼�����ģ�飬Ŀǰ�����epoll */
    if (module == NULL) {
        for (i = 0; ngx_modules[i]; i++) {

            if (ngx_modules[i]->type != NGX_EVENT_MODULE) {
                continue;
            }

            event_module = ngx_modules[i]->ctx;

            if (ngx_strcmp(event_module->name->data, event_core_name.data) == 0)
            {
                continue;
            }

            module = ngx_modules[i];
            break;
        }
    }

    if (module == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "no events module found");
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_uint_value(ecf->connections, DEFAULT_CONNECTIONS);		/* [analy]	�����ļ���δָ��ʱ��Ĭ��Ϊ512 */	
    cycle->connection_n = ecf->connections;

    ngx_conf_init_uint_value(ecf->use, module->ctx_index);					/* [analy]	Ĭ�ϸ���ϵͳ�����¼�ģ���趨 */

	
	/* [analy]	��ȡģ��������(ngx_epoll_module_ctx, �����epoll) */
    event_module = module->ctx;
    ngx_conf_init_ptr_value(ecf->name, event_module->name->data);			/* [analy]	Ĭ����epoll */

    ngx_conf_init_value(ecf->multi_accept, 0);
    ngx_conf_init_value(ecf->accept_mutex, 1);								/* [analy]	Ĭ���Ǵ�on */	
    ngx_conf_init_msec_value(ecf->accept_mutex_delay, 500);					/* [analy]	Ĭ��500ms */	
	

#if (NGX_HAVE_RTSIG)

    if (!rtsig) {
        return NGX_CONF_OK;
    }

    if (ecf->accept_mutex) {
        return NGX_CONF_OK;
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf->worker_processes == 0) {
        return NGX_CONF_OK;
    }

    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "the \"rtsig\" method requires \"accept_mutex\" to be on");

    return NGX_CONF_ERROR;

#else

    return NGX_CONF_OK;

#endif
}