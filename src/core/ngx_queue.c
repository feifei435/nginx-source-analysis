
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * find the middle queue element if the queue has odd number of elements
 * or the first element of the queue's second part otherwise
 */

ngx_queue_t *
ngx_queue_middle(ngx_queue_t *queue)
{
    ngx_queue_t  *middle, *next;

    middle = ngx_queue_head(queue);

    if (middle == ngx_queue_last(queue)) {
        return middle;
    }

    next = ngx_queue_head(queue);

    for ( ;; ) {
        middle = ngx_queue_next(middle);

        next = ngx_queue_next(next);

        if (next == ngx_queue_last(queue)) {
            return middle;
        }

        next = ngx_queue_next(next);

        if (next == ngx_queue_last(queue)) {
            return middle;
        }
    }
}


/* the stable insertion sort */

/*
 *	[analy]	队列排序采用的是稳定的简单插入排序方法，即从第一个节点开始遍历，依次将当前节点(q)插入前面已经排好序的队列(链表)中
 *			由于排序仅简单的修改了指针指向的操作，所以效率较高的。
 */
void
ngx_queue_sort(ngx_queue_t *queue,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *))
{
    ngx_queue_t  *q, *prev, *next;

    q = ngx_queue_head(queue);				

    if (q == ngx_queue_last(queue)) {			//	第一个节点和最后一个节点相等，不需要排序（有0或1个节点）
        return;
    }


    for (q = ngx_queue_next(q); q != ngx_queue_sentinel(queue); q = next) {

        prev = ngx_queue_prev(q);			//	取当前节点的前一个节点
        next = ngx_queue_next(q);			//	取当前节点的后一个节点

        ngx_queue_remove(q);				//	删除当前节点

        do {
            if (cmp(prev, q) <= 0) {
                break;
            }

            prev = ngx_queue_prev(prev);	//	这里取前一个节点的目的是为了检查循环条件是否成立，如果成立说明头节点之后还有节点，需要继续比较
            								//	不成立，说明头结点之后已经无接点，直接插入到头结点后

        } while (prev != ngx_queue_sentinel(queue));	

        ngx_queue_insert_after(prev, q);					
    }
}
