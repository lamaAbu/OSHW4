//Part 1 – Naïve Malloc
#include <unistd.h>

#define CURRENT 0
#define MAX_SIZE 100000000
#define FAILED_SBRK_SYSCALL (void*)(-1)


/*
Tries to allocate ‘size’ bytes.
● Return value:
i. Success –
    a pointer to the first allocated byte within the allocated block.
ii. Failure –
    a. If ‘size’ is 0 returns NULL.
    b. If ‘size’ is more than 10^8, return NULL.
    c. If sbrk fails, return NULL. 
*/
void* smalloc (size_t size)
{
    // case a
    if(size == 0)
        return NULL;

    // case b
    else if(size > MAX_SIZE)
        return NULL;

    //case c
    void* new_memory_ptr = sbrk(size);
    if(new_memory_ptr == FAILED_SBRK_SYSCALL)
        return NULL;

    // success
    return new_memory_ptr;
}