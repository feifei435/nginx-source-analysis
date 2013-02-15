
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_SLAB_PAGE_MASK   3
#define NGX_SLAB_PAGE        0
#define NGX_SLAB_BIG         1
#define NGX_SLAB_EXACT       2
#define NGX_SLAB_SMALL       3

#if (NGX_PTR_SIZE == 4)

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffff
#define NGX_SLAB_PAGE_START  0x80000000

#define NGX_SLAB_SHIFT_MASK  0x0000000f
#define NGX_SLAB_MAP_MASK    0xffff0000
#define NGX_SLAB_MAP_SHIFT   16

#define NGX_SLAB_BUSY        0xffffffff

#else /* (NGX_PTR_SIZE == 8) */

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffffffffffff
#define NGX_SLAB_PAGE_START  0x8000000000000000

#define NGX_SLAB_SHIFT_MASK  0x000000000000000f
#define NGX_SLAB_MAP_MASK    0xffffffff00000000
#define NGX_SLAB_MAP_SHIFT   32

#define NGX_SLAB_BUSY        0xffffffffffffffff

#endif


#if (NGX_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)     ngx_memset(p, 0xA5, size)

#else

#if (NGX_HAVE_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)                                                \
    if (ngx_debug_malloc)          ngx_memset(p, 0xA5, size)

#else

#define ngx_slab_junk(p, size)

#endif

#endif

static ngx_slab_page_t *ngx_slab_alloc_pages(ngx_slab_pool_t *pool,
    ngx_uint_t pages);
static void ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages);
static void ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level,
    char *text);


static ngx_uint_t  ngx_slab_max_size;			//	页的一半大小（2048 | 4096）
static ngx_uint_t  ngx_slab_exact_size;			//	一页中一个块的大小
static ngx_uint_t  ngx_slab_exact_shift;		//	ngx_slab_exact_size的二进制0的位数（128 - 7）

//	共享内存的slab_poll初始化，主要是初始化slot数组和pages数组。
void
ngx_slab_init(ngx_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    ngx_int_t         m;
    ngx_uint_t        i, n, pages;
    ngx_slab_page_t  *slots;

    /* STUB */
    if (ngx_slab_max_size == 0) {

        ngx_slab_max_size = ngx_pagesize / 2;

		//	计算一个内存页中可容纳的块的大小（uintptr_t类型大小是自适应的，会根据系统进行调整，一页可以被划分成32块或64块，每块大小是128byte)
        ngx_slab_exact_size = ngx_pagesize / (8 * sizeof(uintptr_t));			

		//	块大小的偏移(1000 0000)
        for (n = ngx_slab_exact_size; n >>= 1; ngx_slab_exact_shift++) {
            /* void */
        }
    }

	//	8字节
    pool->min_size = 1 << pool->min_shift;

	//	p ---> 
    p = (u_char *) pool + sizeof(ngx_slab_pool_t);
    size = pool->end - p;								//	除结构 ngx_slab_pool_t 以外的剩余共享内存空间

    ngx_slab_junk(p, size);

    slots = (ngx_slab_page_t *) p;

	//	计算需要的槽数量（12-3），按照大小分配9个层次（8、16、32、64、128、256、512、1024、2048）
    n = ngx_pagesize_shift - pool->min_shift;			

    for (i = 0; i < n; i++) {
        slots[i].slab = 0;
        slots[i].next = &slots[i];
        slots[i].prev = 0;
    }

    p += n * sizeof(ngx_slab_page_t);					//	p指向 ngx_slab_pool_t + （n * ngx_slab_page_t） 后地址

	//	????
    pages = (ngx_uint_t) (size / (ngx_pagesize + sizeof(ngx_slab_page_t)));

    ngx_memzero(p, pages * sizeof(ngx_slab_page_t));

	//	指向pages部分
	pool->pages = (ngx_slab_page_t *) p;

    pool->free.prev = 0;
    pool->free.next = (ngx_slab_page_t *) p;	//	指向pages部分

	//	设置pages部分中第一项
	pool->pages->slab = pages;
    pool->pages->next = &pool->free;
	pool->pages->prev = (uintptr_t) &pool->free;

    pool->start = (u_char *)
                  ngx_align_ptr((uintptr_t) p + pages * sizeof(ngx_slab_page_t),
                                 ngx_pagesize);

	//	???
    m = pages - (pool->end - pool->start) / ngx_pagesize;
    if (m > 0) {
        pages -= m;
        pool->pages->slab = pages;
    }

    pool->log_ctx = &pool->zero;
    pool->zero = '\0';
}


void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    ngx_shmtx_lock(&pool->mutex);

    p = ngx_slab_alloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


void *
ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, n, m, mask, *bitmap;
    ngx_uint_t        i, slot, shift, map;
    ngx_slab_page_t  *page, *prev, *slots;


// #############	如果申请的大小 >= 半页，则我们需要计算出需要的page数，然后从空闲页中分配出连续的几个可用页
    if (size >= ngx_slab_max_size) {

        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                       "slab alloc: %uz", size);

		page = ngx_slab_alloc_pages(pool, (size + ngx_pagesize - 1)
                                          >> ngx_pagesize_shift);
        if (page) {
            p = (page - pool->pages) << ngx_pagesize_shift;				//	(page - pool->pages) 得到距开始page的几个page页，在乘以4096或8192（p的值应该是4096或8192的倍数）
            p += (uintptr_t) pool->start;

        } else {
            p = 0;
        }

        goto done;
    }

// #############	如果申请的大小 < 半页，则启用slab分配算法进行分配

    if (size > pool->min_size) {

		//	申请的空间大于最小值，计算slot位置

        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
        slot = shift - pool->min_shift;

    } else {
        size = pool->min_size;
        shift = pool->min_shift;
        slot = 0;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %uz slot: %ui", size, slot);

	//	获取slots地址
    slots = (ngx_slab_page_t *) ((u_char *) pool + sizeof(ngx_slab_pool_t));
    page = slots[slot].next;				

	//	slot的next指针初始化时指向自身地址，当此slot被使用时将指向使用的页地址
    if (page->next != page) {

        if (shift < ngx_slab_exact_shift) {

            do {
                p = (page - pool->pages) << ngx_pagesize_shift;
                bitmap = (uintptr_t *) (pool->start + p);

                map = (1 << (ngx_pagesize_shift - shift))
                          / (sizeof(uintptr_t) * 8);

                for (n = 0; n < map; n++) {

                    if (bitmap[n] != NGX_SLAB_BUSY) {

                        for (m = 1, i = 0; m; m <<= 1, i++) {
                            if ((bitmap[n] & m)) {
                                continue;
                            }

                            bitmap[n] |= m;

                            i = ((n * sizeof(uintptr_t) * 8) << shift)
                                + (i << shift);

                            if (bitmap[n] == NGX_SLAB_BUSY) {
                                for (n = n + 1; n < map; n++) {
                                     if (bitmap[n] != NGX_SLAB_BUSY) {
                                         p = (uintptr_t) bitmap + i;

                                         goto done;
                                     }
                                }

                                prev = (ngx_slab_page_t *)
                                            (page->prev & ~NGX_SLAB_PAGE_MASK);
                                prev->next = page->next;
                                page->next->prev = page->prev;

                                page->next = NULL;
                                page->prev = NGX_SLAB_SMALL;
                            }

                            p = (uintptr_t) bitmap + i;

                            goto done;
                        }
                    }
                }

                page = page->next;

            } while (page);

        } else if (shift == ngx_slab_exact_shift) {

            do {
                if (page->slab != NGX_SLAB_BUSY) {

                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if ((page->slab & m)) {
                            continue;
                        }

						/*	由于申请的空间等于128，一个内存页可以容纳32或64个，
							使用 uintptr_t slab 变量的对应位可以标识出每个块的状态 ，
							page->slab的对应位为1时，表示此块已被使用  */
                        page->slab |= m;

						//	page页已经全部分配出去了
                        if (page->slab == NGX_SLAB_BUSY) {
                            prev = (ngx_slab_page_t *)					//	之前被设置为 &slots[slot] | NGX_SLAB_EXACT，此时获取的是关联的slot的位置
                                            (page->prev & ~NGX_SLAB_PAGE_MASK);
                            prev->next = page->next;					//	slot->next指向了自己
                            page->next->prev = page->prev;				//	slot->prev保存了slot[i] | NGX_SLAB_EXACT

                            page->next = NULL;
                            page->prev = NGX_SLAB_EXACT;
                        }

                        p = (page - pool->pages) << ngx_pagesize_shift;		//	计算页的偏移量（e.g.  4 * 4096)
                        p += i << shift;									//	"i" 是128的个数
                        p += (uintptr_t) pool->start;

                        goto done;
                    }
                }

				//	指向slot的位置
                page = page->next;

            } while (page);

        } else { /* shift > ngx_slab_exact_shift */

            n = ngx_pagesize_shift - (page->slab & NGX_SLAB_SHIFT_MASK);
            n = 1 << n;
            n = ((uintptr_t) 1 << n) - 1;
            mask = n << NGX_SLAB_MAP_SHIFT;

            do {
                if ((page->slab & NGX_SLAB_MAP_MASK) != mask) {

                    for (m = (uintptr_t) 1 << NGX_SLAB_MAP_SHIFT, i = 0;
                         m & mask;
                         m <<= 1, i++)
                    {
                        if ((page->slab & m)) {
                            continue;
                        }

                        page->slab |= m;

                        if ((page->slab & NGX_SLAB_MAP_MASK) == mask) {
                            prev = (ngx_slab_page_t *)									//	之前被设置为 &slots[slot] | NGX_SLAB_EXACT，此时获取的是关联的slot的位置
                                            (page->prev & ~NGX_SLAB_PAGE_MASK);
                            prev->next = page->next;									//	slot->next指向了自己
                            page->next->prev = page->prev;								//	slot->prev保存了slot[i] | NGX_SLAB_EXACT

                            page->next = NULL;
                            page->prev = NGX_SLAB_BIG;
                        }

                        p = (page - pool->pages) << ngx_pagesize_shift;
                        p += i << shift;
                        p += (uintptr_t) pool->start;

                        goto done;
                    }
                }

                page = page->next;

            } while (page);
        }
    }

	//	申请一个页面
    page = ngx_slab_alloc_pages(pool, 1);

    if (page) {

		//	申请的空间小于128
        if (shift < ngx_slab_exact_shift) {

			//	(page - pool->pages) 得到距开始page的几个page页，在乘以4096或8192（p的值应该是4096或8192的倍数）
            p = (page - pool->pages) << ngx_pagesize_shift;			
            bitmap = (uintptr_t *) (pool->start + p);				//	得到当前内存页的首地址

            s = 1 << shift;											//	得到当前分段最大空间大小
            n = (1 << (ngx_pagesize_shift - shift)) / 8 / s;		//	????

            if (n == 0) {
                n = 1;
            }

			//	3
            bitmap[0] = (2 << n) - 1;		//	???

			//	4
            map = (1 << (ngx_pagesize_shift - shift)) / (sizeof(uintptr_t) * 8);	//	??

            for (i = 1; i < map; i++) {
                bitmap[i] = 0;
            }

			page->slab = shift;				//	
			page->next = &slots[slot];		//	page与slot相互关联
			page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;

			//	设置slot->next指向当前使用的页
            slots[slot].next = page;

            p = ((page - pool->pages) << ngx_pagesize_shift) + s * n;
            p += (uintptr_t) pool->start;

            goto done;

		//	申请的空间等于128
        } else if (shift == ngx_slab_exact_shift) {

			/*	内存默认按照4字节或8字节对齐，&slots[1...N]返回的内存地址均是4或8的倍数（） 
				prev指针的后2位会被用来保存当前的page对应的类型	*/
            page->slab = 1;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;			

            slots[slot].next = page;

            p = (page - pool->pages) << ngx_pagesize_shift;			
            p += (uintptr_t) pool->start;

            goto done;


		//	申请的空间大于128
        } else { /* shift > ngx_slab_exact_shift */

            page->slab = ((uintptr_t) 1 << NGX_SLAB_MAP_SHIFT) | shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;

            slots[slot].next = page;

            p = (page - pool->pages) << ngx_pagesize_shift;
            p += (uintptr_t) pool->start;

            goto done;
        }
    }

    p = 0;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0, "slab alloc: %p", p);

    return (void *) p;
}


void
ngx_slab_free(ngx_slab_pool_t *pool, void *p)
{
    ngx_shmtx_lock(&pool->mutex);

    ngx_slab_free_locked(pool, p);

    ngx_shmtx_unlock(&pool->mutex);
}


void
ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    ngx_uint_t        n, type, slot, shift, map;
    ngx_slab_page_t  *slots, *page;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0, "slab free: %p", p);

    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): outside of pool");
        goto fail;
    }

    n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
    page = &pool->pages[n];
    slab = page->slab;
    type = page->prev & NGX_SLAB_PAGE_MASK;				//	获取slab类型

    switch (type) {

    case NGX_SLAB_SMALL:

        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        n = ((uintptr_t) p & (ngx_pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n & (sizeof(uintptr_t) * 8 - 1));
        n /= (sizeof(uintptr_t) * 8);
        bitmap = (uintptr_t *) ((uintptr_t) p & ~(ngx_pagesize - 1));

        if (bitmap[n] & m) {

            if (page->next == NULL) {
                slots = (ngx_slab_page_t *)
                                   ((u_char *) pool + sizeof(ngx_slab_pool_t));
                slot = shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | NGX_SLAB_SMALL;
            }

            bitmap[n] &= ~m;

            n = (1 << (ngx_pagesize_shift - shift)) / 8 / (1 << shift);

            if (n == 0) {
                n = 1;
            }

            if (bitmap[0] & ~(((uintptr_t) 1 << n) - 1)) {
                goto done;
            }

            map = (1 << (ngx_pagesize_shift - shift)) / (sizeof(uintptr_t) * 8);

            for (n = 1; n < map; n++) {
                if (bitmap[n]) {
                    goto done;
                }
            }

            ngx_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_EXACT:

        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (ngx_pagesize - 1)) >> ngx_slab_exact_shift);
        size = ngx_slab_exact_size;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        if (slab & m) {
            if (slab == NGX_SLAB_BUSY) {
                slots = (ngx_slab_page_t *)
                                   ((u_char *) pool + sizeof(ngx_slab_pool_t));
                slot = ngx_slab_exact_shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | NGX_SLAB_EXACT;
            }

            page->slab &= ~m;

            if (page->slab) {
                goto done;
            }

            ngx_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_BIG:

        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        m = (uintptr_t) 1 << ((((uintptr_t) p & (ngx_pagesize - 1)) >> shift)
                              + NGX_SLAB_MAP_SHIFT);

        if (slab & m) {

            if (page->next == NULL) {
                slots = (ngx_slab_page_t *)
                                   ((u_char *) pool + sizeof(ngx_slab_pool_t));
                slot = shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;
                page->next->prev = (uintptr_t) page | NGX_SLAB_BIG;
            }

            page->slab &= ~m;

            if (page->slab & NGX_SLAB_MAP_MASK) {
                goto done;
            }

            ngx_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_PAGE:

        if ((uintptr_t) p & (ngx_pagesize - 1)) {
            goto wrong_chunk;
        }

        if (slab == NGX_SLAB_PAGE_FREE) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): page is already free");
            goto fail;
        }

        if (slab == NGX_SLAB_PAGE_BUSY) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): pointer to wrong page");
            goto fail;
        }

        n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
        size = slab & ~NGX_SLAB_PAGE_START;

        ngx_slab_free_pages(pool, &pool->pages[n], size);

        ngx_slab_junk(p, size << ngx_pagesize_shift);

        return;
    }

    /* not reached */

    return;

done:

    ngx_slab_junk(p, size);

    return;

wrong_chunk:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): pointer to wrong chunk");

    goto fail;

chunk_already_free:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): chunk is already free");

fail:

    return;
}


static ngx_slab_page_t *
ngx_slab_alloc_pages(ngx_slab_pool_t *pool, ngx_uint_t pages)
{
    ngx_slab_page_t  *page, *p;

	//	
    for (page = pool->free.next; page != &pool->free; page = page->next) {

        if (page->slab >= pages) {

            if (page->slab > pages) {

				//	设置空闲pages中的第一个管理结构属性
                page[pages].slab = page->slab - pages;		//	剩余空闲 page 页数
                page[pages].next = page->next;				//	指向 &page->free
                page[pages].prev = page->prev;				//	保存 page->free 的地址

				//	对pool->free字段进行赋值 (由于page->prev保存的是pool->free的地址, 所以指针p指向的就是pool->free）
                p = (ngx_slab_page_t *) page->prev;			
                p->next = &page[pages];								//	使pool->free->next 指向未使用的空闲page页
                page->next->prev = (uintptr_t) &page[pages];		//	保存空闲page起始块的地址

            } else {
                p = (ngx_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }

			//	对申请的page进行初始化赋值
            page->slab = pages | NGX_SLAB_PAGE_START;
            page->next = NULL;
            page->prev = NGX_SLAB_PAGE;

            if (--pages == 0) {
                return page;
            }

            for (p = page + 1; pages; pages--) {
                p->slab = NGX_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = NGX_SLAB_PAGE;
                p++;
            }

            return page;
        }
    }

    ngx_slab_error(pool, NGX_LOG_CRIT, "ngx_slab_alloc() failed: no memory");

    return NULL;
}


static void
ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages)
{
    ngx_slab_page_t  *prev;

    page->slab = pages--;

    if (pages) {		//	两个以上的page要回收时，除第一个以外其余均初始化为0
        ngx_memzero(&page[1], pages * sizeof(ngx_slab_page_t));
    }

    if (page->next) {
        prev = (ngx_slab_page_t *) (page->prev & ~NGX_SLAB_PAGE_MASK);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

    page->prev = (uintptr_t) &pool->free;
    page->next = pool->free.next;

    page->next->prev = (uintptr_t) page;

    pool->free.next = page;
}


static void
ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level, char *text)
{
    ngx_log_error(level, ngx_cycle->log, 0, "%s%s", text, pool->log_ctx);
}
