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

	//how to line the free blocks
	struct block_meta* ptr = NULL;
	if (size < MMAP_THRESHOLD) {
		while (current) {
			if (current->status == STATUS_FREE) {
				if (ptr == NULL) {
					ptr = current;
				} else {
					ptr->size += current->size;
					ptr->next = current->next;
					if (current->next)
						current->next->prev = ptr;
				}
				current = ptr->next;
			} else {
					current = current->next;
				}
		}
		current = global_base;
	}
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
	/* TODO: Implement os_malloc */
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
		if (!last->next && last->status != STATUS_FREE) { //if the last block of memory was already freed it will brk again
			block = request_space(last, block_size);
			if (!block)
				return NULL;
		} else {
			//found a free block-> split the block here
			// what happens if the block found doesnt have enough size
			// to hold a bigger block: call sbrk again
			// SPLIT not correctly implemented => ifs are not correct
			size_t new_size;
			struct block_meta *new;
			if (block_size >= last->size) {
				new_size = ALIGN(block_size - last->size);
				new = sbrk(new_size);
				if (new == (void *) -1)
					return NULL;
				last->size += new_size;
				last->status = STATUS_ALLOC;
				block = last;
				return (block + 1);
			}
			if (block_size < last->size) { //see here when to call sbrk if the remaining size is not enough
				size_t remaining_size = last->size - block_size;
				if (remaining_size <= ALIGN(META_SIZE) + ALIGN(sizeof(char))) {
					last->status = STATUS_ALLOC;
					block = last;
					return (block + 1);
				}
				// HOW TO SPLIT THE BLOCK?
				last->size = block_size + ALIGN(META_SIZE);

				// Calculate the address of the new free block
				struct block_meta *new_block = (struct block_meta *)((char *)(last + 1) + block_size);
				
				new_block->status = STATUS_FREE;
				new_block->size = ALIGN(remaining_size) - ALIGN(META_SIZE);
				new_block->prev = last;
				new_block->next = last->next;

				// Update the next block's prev pointer if it exists
				if (last->next) {
					last->next->prev = new_block;
				}

				last->next = new_block;
				last->status = STATUS_ALLOC;
				block = last;
				return (block + 1);
			}
			// if (block_size == last->size) {
			// 	new_size = ALIGN(META_SIZE);
			// 	new = sbrk(new_size);
			// 	if (new == (void *)-1)
			// 		return NULL;
			// 	last->size += new_size;
			// 	last->status = STATUS_ALLOC;
			// 	block = last;
			// 	return (block + 1);
			// }
		}
	}
	if (block_size >= MMAP_THRESHOLD) { //doesnt work because find_free_block searches in global_base
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
		//block_ptr->size = 0;
		
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
