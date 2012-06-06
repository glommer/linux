/*
 * Slab allocator functions that are independent of the allocator strategy
 *
 * (C) 2012 Christoph Lameter <cl@linux.com>
 */
#include <linux/slab.h>

#include <linux/mm.h>
#include <linux/poison.h>
#include <linux/interrupt.h>
#include <linux/memory.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <linux/memcontrol.h>

#include "slab.h"

enum slab_state slab_state;
LIST_HEAD(slab_caches);
DEFINE_MUTEX(slab_mutex);
struct kmem_cache *kmem_cache;

/*
 * Figure out what the alignment of the objects will be given a set of
 * flags, a user specified alignment and the size of the objects.
 */
unsigned long calculate_alignment(unsigned long flags,
		unsigned long align, unsigned long size)
{
	/*
	 * If the user wants hardware cache aligned objects then follow that
	 * suggestion if the object is sufficiently large.
	 *
	 * The hardware cache alignment cannot override the specified
	 * alignment though. If that is greater then use it.
	 */
	if (flags & SLAB_HWCACHE_ALIGN) {
		unsigned long ralign = cache_line_size();
		while (size <= ralign / 2)
			ralign /= 2;
		align = max(align, ralign);
	}

	if (align < ARCH_SLAB_MINALIGN)
		align = ARCH_SLAB_MINALIGN;

	return ALIGN(align, sizeof(void *));
}


/*
 * kmem_cache_create - Create a cache.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @align: The required alignment for the objects.
 * @flags: SLAB flags
 * @ctor: A constructor for the objects.
 *
 * Returns a ptr to the cache on success, NULL on failure.
 * Cannot be called within a interrupt, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache.
 *
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red' zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 */

struct kmem_cache *
kmem_cache_create_memcg(struct mem_cgroup *memcg, const char *name, size_t size,
			size_t align, unsigned long flags, void (*ctor)(void *),
			struct kmem_cache *parent_cache)
{
	struct kmem_cache *s = NULL;
	char *n;
	int r;

#ifdef CONFIG_DEBUG_VM
	if (!name || in_interrupt() || size < sizeof(void *) ||
		size > KMALLOC_MAX_SIZE) {
		printk(KERN_ERR "kmem_cache_create(%s) integrity check"
			" failed\n", name);
		goto out;
	}
#endif

	get_online_cpus();
	mutex_lock(&slab_mutex);

#ifdef CONFIG_DEBUG_VM
	list_for_each_entry(s, &slab_caches, list) {
		char tmp;
		int res;

		/*
		 * This happens when the module gets unloaded and doesn't
		 * destroy its slab cache and no-one else reuses the vmalloc
		 * area of the module.  Print a warning.
		 */
		res = probe_kernel_address(s->name, tmp);
		if (res) {
			printk(KERN_ERR
			       "Slab cache with size %d has lost its name\n",
			       s->object_size);
			continue;
		}

		if (cache_match_memcg(s, memcg) && !strcmp(s->name, name)) {
			printk(KERN_ERR "kmem_cache_create(%s): Cache name"
				" already exists.\n",
				name);
			dump_stack();
			s = NULL;
			goto oops;
		}
	}

	WARN_ON(strchr(name, ' '));	/* It confuses parsers */
#endif

	s = __kmem_cache_alias(memcg, name, size, align, flags, ctor);
	if (s)
		goto oops;

	n = kstrdup(name, GFP_KERNEL);
	if (!n)
		goto oops;

	s = kmem_cache_zalloc(kmem_cache, GFP_KERNEL);

	if (!s) {
		kfree(n);
		goto oops;
	}

	s->name = n;
	s->size = s->object_size = size;
	s->ctor = ctor;
	s->flags = flags;
	s->align = calculate_alignment(flags, align, size);
#ifdef CONFIG_MEMCG_KMEM
	s->memcg_params.memcg = memcg;
	s->memcg_params.parent = parent_cache;
#endif

	r = __kmem_cache_create(s);

	if (!r) {
		s->refcount = 1;
		list_add(&s->list, &slab_caches);
		if (slab_state >= FULL)
			memcg_register_cache(memcg, s);
	}
	else {
		kmem_cache_free(kmem_cache, s);
		kfree(n);
		s = NULL;
	}

oops:
	mutex_unlock(&slab_mutex);
	put_online_cpus();

#ifdef CONFIG_DEBUG_VM
out:
#endif
	if (!s && (flags & SLAB_PANIC))
		panic("kmem_cache_create: Failed to create slab '%s'\n", name);

	return s;
}

struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align,
		unsigned long flags, void (*ctor)(void *))
{
	return kmem_cache_create_memcg(NULL, name, size, align, flags, ctor, NULL);
}
EXPORT_SYMBOL(kmem_cache_create);

void kmem_cache_destroy(struct kmem_cache *s)
{
	get_online_cpus();
	mutex_lock(&slab_mutex);
	list_del(&s->list);

	if (!__kmem_cache_shutdown(s)) {
		if (s->flags & SLAB_DESTROY_BY_RCU)
			rcu_barrier();

		memcg_release_cache(s);
		kfree(s->name);
		kmem_cache_free(kmem_cache, s);
	} else {
		list_add(&s->list, &slab_caches);
		printk(KERN_ERR "kmem_cache_destroy %s: Slab cache still has objects\n",
			s->name);
		dump_stack();
	}
	mutex_unlock(&slab_mutex);
	put_online_cpus();
}
EXPORT_SYMBOL(kmem_cache_destroy);

int slab_is_available(void)
{
	return slab_state >= UP;
}

static int __init kmem_cache_initcall(void)
{
	int r = __kmem_cache_initcall();
#ifdef CONFIG_MEMCG_KMEM
	struct kmem_cache *s;

	if (r)
		return r;
	mutex_lock(&slab_mutex);
	list_for_each_entry(s, &slab_caches, list)
		memcg_register_cache(NULL, s);
	mutex_unlock(&slab_mutex);
#endif
	return r;
}
__initcall(kmem_cache_initcall);
