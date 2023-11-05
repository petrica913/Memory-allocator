// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <assert.h>
#include <unistd.h>
#include "block_meta.h"
#include "osmem.h"

#define MMAP_THRESHOLD		(128 * 1024)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define META_SIZE sizeof(struct block_meta)

void *global_base = NULL;
int ok = 0; //if the heap preallocation was made

struct block_meta *find_free_block(struct block_meta **last, size_t size) { //have to search for a free a block
	struct block_meta *current = global_base;
	while (current && !(current->status && current->size >= size)) {
		*last = current;
		current = current->next;
	}
	return current;
}

struct block_meta *request_space (struct block_meta *last, size_t size) {
	if (size == 0)
		return NULL;
	struct block_meta *block;
	void *request;
	if (size < MMAP_THRESHOLD && ok != 0) {
		block = sbrk(META_SIZE + size);
		if (block == (void*) -1)
			return NULL;
		block->status = STATUS_ALLOC;
	}
	if (size < MMAP_THRESHOLD && ok == 0) {
		block = sbrk(MMAP_THRESHOLD);
		ok++;
		block->size = MMAP_THRESHOLD;
		block->next = NULL;
		block->prev = last;
		return block;
	}
	if (size >= MMAP_THRESHOLD) {
		request = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		block = (struct block_metadata*) request;
		assert((void*)block == request);
		if (request == (void*) -1)
			return NULL;
		block->status = STATUS_MAPPED;
	}
	if (last)
		last->next = block;
	if (!block)
		return NULL;
	block->size = size;
	block->next = NULL;
	block->prev = last;
	return block;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	struct block_meta *block;
	size_t block_size = ALIGN(size);
	if (block_size < 0)
		return NULL;
	if (!global_base) {
		block = request_space(NULL, size);
		if (!block)
			return NULL;
		global_base = block;
	} else { //bad implementation
		struct block_meta *last = global_base;
		block = find_free_block(&last, block_size);
		if (!block) {
			block = request_space(last, block_size);
			if (!block)
				return NULL;
		} else {
			//found a free block-> split the block here
			block->status = STATUS_FREE;
		}
	}
	return (block + 1);
}

struct block_meta *get_block_ptr(void *ptr) {
	return (struct block_meta*)ptr - 1;
}

void os_free(void *ptr) {
    if (!ptr)
        return;

    struct block_meta *block_ptr = get_block_ptr(ptr);

    if (block_ptr->status == STATUS_ALLOC) {
        // If it was allocated using brk(), use sbrk() to deallocate.
        block_ptr->status = STATUS_FREE;
    } else if (block_ptr->status == STATUS_MAPPED) {
        // If it was allocated using mmap(), use munmap() to deallocate.
        munmap(block_ptr, block_ptr->size + META_SIZE);
    }

    // Set the block status to FREE.
    //block_ptr->status = STATUS_FREE;
}


void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
