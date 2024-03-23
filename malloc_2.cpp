//Part 2 – Basic Malloc
#include <unistd.h>

#define CURRENT 0
#define MAX_SIZE 100000000
#define FAILED_SBRK_SYSCALL (void*)(-1)



struct MallocMetadata 
{
    size_t size; // should it be const?
    bool is_free;
    MallocMetadata* next;
    MallocMetadata* prev;
};


void* smalloc(size_t size)
{
    if(size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }

}


//You should use std::memset for setting values to 0 in your scalloc().
void* scalloc(size_t num, size_t size)
{
    if(size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }

}

void sfree(void* p)
{

}


//You should use std::memmove for copying data in srealloc().
void* srealloc(void* oldp, size_t size)
{
    if(size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }
}


//******************************************************************************* HIDDEN FUNCS **********************************************************
size_t _num_free_blocks()
{

}

size_t _num_free_bytes()
{

}

size_t _num_allocated_blocks()
{

}

size_t _num_allocated_bytes()
{
    
}

size_t _num_meta_data_bytes()
{
    
}

size_t _size_meta_data()
{

}