// Part 2 – Basic Malloc
#include <unistd.h>

#define MAX_SIZE 100000000
#define FAILED_SBRK_SYSCALL (void *)(-1)

class MallocMetadata
{
public:
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
};

// MallocMetadata::MallocMetadata()
//{
//  size = 0;
//  is_free = false;
//  next = NULL;
//   prev = NULL;
//}

class MeList
{
public:
    MallocMetadata *dummy_head;
    int length;
    size_t free_blocks;
    size_t free_bytes;
    size_t allocated_bytes;

public:
    MeList(); // constructor
    void append(MallocMetadata *element);
};

MeList ::MeList() : length(0), free_blocks(0), free_bytes(0), allocated_bytes(0)
{
    dummy_head = NULL;
}

void MeList ::append(MallocMetadata *element)
{
    MallocMetadata *current_node = dummy_head;
    for (int i = 0; i < length; i++)
    {
        current_node = current_node->next;
    }
    // now current_node points to the last node in me_list
    current_node->next = element;
    element->prev = current_node;
    allocated_bytes += element->size;
    length++;
}

//*********************************************************************************** FUNCS ************************************************************
MeList *me_list;

void *smalloc(size_t size)
{
    if (size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }

    MallocMetadata *cur_node = me_list->dummy_head;
    for (int i = 0; i <= me_list->length; i++)
    {
        cur_node = cur_node->next;
        if ((!cur_node) && cur_node->is_free)
        {
            if (size <= cur_node->size)
            {
                // we should mark all node ad used?
                cur_node->is_free = false;

                // updating data
                me_list->free_blocks--;
                me_list->free_bytes -= cur_node->size;
                me_list->allocated_bytes += cur_node->size;
                return (void *)((char *)cur_node + sizeof(MallocMetadata));
            }
        }
    }
    // we should allocate new size
    void *new_memory = sbrk(size + sizeof(MallocMetadata));
    if (new_memory == FAILED_SBRK_SYSCALL)
        return NULL;

    // update list data
    me_list->append((MallocMetadata *)new_memory);
    return (void *)((char *)new_memory + sizeof(MallocMetadata));
}

// You should use std::memset for setting values to 0 in your scalloc().
void *scalloc(size_t num, size_t size)
{
    void *ptr = smalloc(num * size);
    if (!ptr)
        return NULL;
    memset(ptr, 0, num * size);
    return ptr;
}

void sfree(void *p)
{
    if (!p)
        return;
    MallocMetadata *ptr = (MallocMetadata *)((char *)p - sizeof(MallocMetadata));
    if (ptr->is_free)
        return;
    ptr->is_free = true;
    me_list->free_blocks++;
    me_list->free_bytes += ptr->size;
    return;
}

// You should use std::memmove for copying data in srealloc().
void *srealloc(void *oldp, size_t size)
{
    if (size == 0 || size > MAX_SIZE)
        return NULL;

    else if (!(oldp))
        return smalloc(size);

    MallocMetadata *oldPtr = (MallocMetadata *)((char *)oldp - sizeof(MallocMetadata));
    if (size <= oldPtr->size)
        return oldp;

    void *ptr = smalloc(size);
    if (!ptr)
        return NULL;
    memmove(ptr, oldp, size);
    sfree(oldp);
    return ptr;
}

//******************************************************************************* HIDDEN FUNCS **********************************************************
size_t _num_free_blocks()
{
    return me_list->free_blocks;
}

size_t _num_free_bytes()
{
    return me_list->free_bytes;
}

size_t _num_allocated_blocks()
{
    return (size_t)me_list->length;
}

size_t _num_allocated_bytes()
{
    return me_list->allocated_bytes;
}

size_t _num_meta_data_bytes()
{
    return (size_t)(sizeof(MallocMetadata) * me_list->length);
}

size_t _size_meta_data()
{
    return (size_t)(sizeof(MallocMetadata));
}