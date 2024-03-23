//Part 2 – Basic Malloc
#include <unistd.h>

#define CURRENT 0
#define MAX_SIZE 100000000
#define FAILED_SBRK_SYSCALL (void*)(-1)



class MallocMetadata 
{
    public:
    size_t size; // should it be const?
    bool is_free;
    MallocMetadata* next;
    MallocMetadata* prev;

    //MallocMetadata* create_dummy_node();
    MallocMetadata() = default;
};

// MallocMetadata* MallocMetadata:: create_dummy_node()
// {
//     size = 0;
//     is_free = false;
//     next = NULL;
//     prev = NULL;
// }

class MeList
{
    public:
    MallocMetadata* dummy_head;
    int length;
    size_t free_blocks;
    size_t free_bytes;
    size_t allocated_bytes;

    public:
    MeList(); //constructor
    void append(MallocMetadata* element);

};

MeList :: MeList() : length(0),free_blocks(0), free_bytes(0), allocated_bytes(0)
{
    // implementation with dummy node
    dummy_head = MallocMetadata();
}

void MeList :: append(MallocMetadata* element)
{
    MallocMetadata* current_node = dummy_head;
    for(int i = 0; i < length; i++)
    {
        current_node = current_node->next;
    }
    // now current_node points to the last node
    current_node->next = element;

    length++;
    allocated_bytes += element->size;
}


//*********************************************************************************** FUNCS ************************************************************
MeList* me_list = MeList();

void* smalloc(size_t size)
{
    if(size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }
    
    MallocMetadata* cur_node = me_list->dummy_head;
    for(int i = 0; i <= me_list->length; i++)
    {
        cur_node = cur_node->next;
        if(cur_node->is_free)
        {
            if(size <= cur_node->size)
            {

            }
        }
    }
    // we should allocate new size
    if(sbrk(size) == FAILED_SBRK_SYSCALL)
    {
        return FAILED_SBRK_SYSCALL;
    }
    else
    {
        //update list data
        return sbrk(CURRENT);
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