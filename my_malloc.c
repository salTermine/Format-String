#define EXPOSE_REAL_MALLOC
#include <sys/mman.h>
#include <assert.h>
#include "my_malloc.h"

heap_block* head;
heap_block* max_heap_addr;

const int free_hdr_size = sizeof(heap_block);
const int used_hdr_size = sizeof(heap_block) - 2*sizeof(void*);

void heap_delete(heap_block* current)  {
   if (current->next)
      current->next->prev = current->prev;
   if (current->prev)
      current->prev->next = current->next;
   if (head == current)
      head = current->next;
}

void heap_insert(heap_block* newblock)  {
   newblock->in_use = 0;
   newblock->prev = NULL;
   newblock->next = head;
   head = newblock;
}

void new_heap_block(heap_block* newblock, int size, int prev_size) {
   newblock->size = size;
   newblock->prev_size = prev_size;
   heap_insert(newblock);
}

// Simple heap implementation: unsorted, doubly-linked list of heap blocks.
// We use the first fit algorithm, but break up blocks that are too large.

#define roundup_double(size)    (size) = ((size)+7) & (~0x7) 
// round up to nearest multiple of 8 bytes

void *my_malloc(size_t size) {
   heap_block* current = head;

   // Find the first block 
   while (current != NULL && current->size < size)
      current = current->next;

   if (current == NULL) return NULL;

   heap_delete(current);

   int size_used = size + used_hdr_size;
   if (current->size > size_used + (size+free_hdr_size)) {//block too large:break
      heap_block* newblock = ((void *)current) + size_used;
      new_heap_block(newblock, current->size - size_used, size);
      current->size = size;
   }

   current->in_use = 1;
   return (void *)(&current->prev);
}

void my_free(void *p) {
   heap_block* current = (heap_block*)(p-used_hdr_size);
   assert(current->in_use);

   // support merging with the following block, but not with prev block
   heap_block* next = (heap_block*)(p+current->size);
   if (next < max_heap_addr) {// otherwise, it is not a valid heap block
      if (!next->in_use) { // it is free, let us merge
         current->size += next->size+free_hdr_size;
         heap_delete(next);
      }
   }

   heap_insert(current);
}

void init_heap(int default_size, int nblocks) {
   if (default_size < 8)
      default_size = 8;
   default_size += free_hdr_size;
   roundup_double(default_size);

   size_t s = default_size*nblocks;
   s = (s+8191) & (~((size_t)8192));

   heap_block* hh = mmap(NULL, s, PROT_EXEC|PROT_READ|PROT_WRITE, 
                         MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
   assert(hh != NULL);

   size_t blksize = s/nblocks;
   for (int i=0; i < nblocks; i++) {
      new_heap_block(hh, blksize-used_hdr_size, blksize-used_hdr_size);
      hh = ((void*)hh) + blksize;
   }
}

__attribute__((constructor))
static void initheap() {
   init_heap(LEN1, 256);
}