
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_QUEUE_H_INCLUDED_
#define _NGX_QUEUE_H_INCLUDED_


typedef struct ngx_queue_s  ngx_queue_t;

struct ngx_queue_s {
    ngx_queue_t  *prev;
    ngx_queue_t  *next;
};


/* 
 *	[analy]	初始化队列 
 */
#define ngx_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q


/* 
 *	[analy]	判断队列是否为空 
 */
#define ngx_queue_empty(h)                                                    \
    (h == (h)->prev)

/* 
 *	[analy]	在头结点之后插入新节点 
 */
#define ngx_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


/* 
 *	[analy]	在当前节点之前插入节点
 */
#define ngx_queue_insert_after   ngx_queue_insert_head

/* 
 *	[analy]	在尾结点之后插入新节点 
 */
#define ngx_queue_insert_tail(h, x)                                           \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x


/* 
 *	[analy]	获取队列的头节点
 */
#define ngx_queue_head(h)                                                     \
    (h)->next

/* 
 *	[analy]	获取队列的尾节点
 */
#define ngx_queue_last(h)                                                     \
    (h)->prev


#define ngx_queue_sentinel(h)                                                 \
    (h)


#define ngx_queue_next(q)                                                     \
    (q)->next


#define ngx_queue_prev(q)                                                     \
    (q)->prev

/* 
 *	[analy]	将节点从所属队列中删除
 */
#if (NGX_DEBUG)

#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

/* 
 *	[analy]	将节点从所属队列中删除
 */
#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif


/* 
 *	[analy]	分割队列 
 *		h为原队列头(即链表头指针)，将该队列从q节点将队列(链表)分割为两个队列(链表)，
 *		q之后的节点组成的新队列的头节点为n
 */
#define ngx_queue_split(h, q, n)                                              \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;


/* 
 *	[analy]	链接队列 
 *		h、n分别为两个队列的指针，即头节点指针，该操作将n队列链接在h队列之后(链接后的队列不包括头结点n)
 */
#define ngx_queue_add(h, n)                                                   \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;

/* 
 *	[analy]	获取节点的数据指针(通过此函数可以找到节点在内存中的地址)
 */
#define ngx_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))


ngx_queue_t *ngx_queue_middle(ngx_queue_t *queue);
void ngx_queue_sort(ngx_queue_t *queue,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *));


#endif /* _NGX_QUEUE_H_INCLUDED_ */
