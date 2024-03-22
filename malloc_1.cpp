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
    if(size == 0)
    {
        // case a
        return NULL;
    }
    else if(size > MAX_SIZE)
    {
        // case b
        return NULL;
    }
    else if(sbrk(size) == FAILED_SBRK_SYSCALL)
    {
        //case c
        return NULL;
    }

    // success
    return sbrk(CURRENT);
}