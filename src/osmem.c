// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include "block_meta.h"
#include "osmem.h"

#define MMAP_THRESHOLD		(128 * 1024)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define META_SIZE sizeof(struct block_meta)

void *global_base = NULL;
int ok = 0; //if the heap preallocation was made
void *mapped_blocks = NULL; //list for holding the mapped blocks

struct block_meta *find_free_block(struct block_meta **last, size_t size) { //have to search for a free a block
	struct block_meta *current;
	if (size >= MMAP_THRESHOLD)
		current = mapped_blocks;
	if (size < MMAP_THRESHOLD)
		current = global_base;
	struct block_meta *best_fit = NULL;
	struct block_meta *ultimate = NULL;
	size_t best_fit_size = SIZE_MAX;

	struct block_meta* ptr = NULL;
	while (current) {
		if (current->status == STATUS_FREE && current->size >= size) {
			if (current->size < best_fit_size) {
				best_fit = current;
				best_fit_size = current->size;
			}
		}
		ultimate = current;
		current = current->next;
	}
	if (!best_fit)
		best_fit = ultimate;
	return best_fit;
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
		block->status = STATUS_ALLOC;
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
	struct block_meta *block;
	size_t block_size = ALIGN(size);
	if (block_size < 0)
		return NULL;
	if (!global_base && block_size < MMAP_THRESHOLD) {
		block = request_space(NULL, block_size);
		if (!block)
			return NULL;
		global_base = block;
	} else if (size < MMAP_THRESHOLD) {
		struct block_meta *last = global_base;
		last = find_free_block(&last, block_size);
		if (!last->next) {
			if (last->status != STATUS_FREE) {
				block = request_space(last, block_size);
				if (!block)
					return NULL;
				return (block + 1);
			}
			if (last->status == STATUS_FREE) {
				struct block_meta *new;
				int dim = block_size - last->size;
				if (dim > 0) {
					new = sbrk(ALIGN(dim));
					last->size += dim;
					last->status = STATUS_ALLOC;
					return last + 1;
				} 
				if (dim == 0) {
					last->status = STATUS_ALLOC;
					return last + 1;
				}
				if (dim < 0) {
					dim = (-1) * dim;
					if (dim < ALIGN(META_SIZE) + ALIGN(1)) {
						last->status = STATUS_ALLOC;
						return last + 1;
					} else {
						struct block_meta *new_block = (struct block_meta *)((char *)(last + 1) + block_size);
						new_block->status = STATUS_FREE;
						new_block->size = last->size - block_size - META_SIZE;
						new_block->prev = last;
						new_block->next = last->next;
						last->size = block_size;
						last->next = new_block;
						last->status = STATUS_ALLOC;
						return last + 1;
					}
				}
			}
		}
		if (block_size <= last->size) {
			size_t remaining_size = last->size - block_size;
			if (remaining_size < ALIGN(META_SIZE) + ALIGN(sizeof(char))) { //cand dai sbrk?
				last->status = STATUS_ALLOC;
				block = last;
				return (block + 1);
			}
			struct block_meta *new_block = (struct block_meta *)((char *)(last + 1) + block_size);
			new_block->status = STATUS_FREE;
			new_block->size = last->size - block_size - META_SIZE;
			new_block->prev = last;
			new_block->next = last->next;
			if (last->next) {
				last->next->prev = new_block;
			}
			last->size = block_size;
			last->next = new_block;
			last->status = STATUS_ALLOC;
			block = last;
			return (block + 1);
		}
	}
	if (block_size >= MMAP_THRESHOLD) {
			if (!mapped_blocks) {
				block = request_space(NULL, block_size);
				if (!block)
					return NULL;
				mapped_blocks = block;
			} else {
				struct block_meta *last = mapped_blocks;
				last = find_free_block(&last, block_size);
				block = request_space(last, block_size);
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
	if (!block_ptr)
		return NULL;

    if (block_ptr->status == STATUS_ALLOC) {
		block_ptr->status = STATUS_FREE;
		if (block_ptr->prev && block_ptr->prev->status == STATUS_FREE) {
			struct block_meta *aux_ptr = block_ptr->next;
			block_ptr->prev->size += block_ptr->size;
			block_ptr->prev->next = block_ptr->next;
			if (aux_ptr)
				aux_ptr->prev = block_ptr->prev;
		}
		if (block_ptr->next && block_ptr->next->status == STATUS_FREE) {
			struct block_meta *aux_ptr = block_ptr->prev;
			block_ptr->next->size += block_ptr->size;
			block_ptr->next->prev = block_ptr->prev;
			if (aux_ptr)
				aux_ptr->next = block_ptr->next;
		}
		
    } else if (block_ptr->status == STATUS_MAPPED) {
		if (block_ptr == mapped_blocks) {
            mapped_blocks = block_ptr->next;
        } else {
            block_ptr->prev->next = block_ptr->next;
            if (block_ptr->next) {
                block_ptr->next->prev = block_ptr->prev;
            }
        }
        munmap(block_ptr, block_ptr->size + META_SIZE);
    }
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
