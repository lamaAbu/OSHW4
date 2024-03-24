//Part 3 - Better Malloc
// Implementing by Buddy Allocator

#include <unistd.h>
#include <string.h>
#include <cmath>

#define MAX_ORDER 10
#define KILO_BYTE 1024
#define MAX_SIZE 100000000
#define INITIAL_BLOCKS_NUM 32
#define BLOCK_SIZE 128 * KILO_BYTE
#define FAILED_SBRK_SYSCALL (void *)(-1)


class MallocMetadata
{
public:
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
};

class MeList
{
public:
    MallocMetadata *dummy_head;
    int length;
    size_t free_blocks;
    size_t free_bytes;
    size_t allocated_bytes;

    MeList(); // constructor
    void append(MallocMetadata *element);
    void remove_head();
};

MeList ::MeList() : length(0), free_blocks(0), free_bytes(0), allocated_bytes(0)
{
    dummy_head = NULL;
}

void MeList ::append(MallocMetadata *element)
{
    MallocMetadata *current_node = dummy_head;
    if (current_node == NULL)
    {
        dummy_head = element;
        element->prev = dummy_head;
        allocated_bytes += element->size;
        length++;
        return;
    }
    for (int i = 0; i < length - 1; i++)
    {
        current_node = current_node->next;
    }

    // now current_node points to the last node in me_list
    current_node->next = element;
    element->prev = current_node;
    allocated_bytes += element->size;
    length++;
}

void MeList:: remove_head()
{
    if(dummy_head == nullptr)
    {
        return;
    }
    else
    {
        MallocMetadata* tmp = dummy_head;
        if(tmp->next != nullptr)
        {
            dummy_head = tmp->next;
            dummy_head->prev = nullptr;
        }
        // should free tmp?
    }
}

//*********************************************************************************** Histogram ************************************************************
MeList* block_lists_arr[MAX_ORDER + 1]; // should we initialize it?

void add_and_merge_buddies(MallocMetadata* element, int order)
{
    // assuming the answer i asked in piaza is yes!
    if(order == MAX_ORDER)
    {
        return;
    }
    if(block_lists_arr[order]->length == 0)
    {
        // we have no other buddies to merge
        block_lists_arr[order]->append(element);
    }
    else
    {
        // i think the length of lists is always 0 or 1, except in max order
        // we should merge
        element->size *= 2;
        block_lists_arr[order]->remove_head();
        add_and_merge_buddies(element, order + 1);
    }

}

void add_to_arr(MallocMetadata* element)
{
    int order = 0;
    while(order < MAX_ORDER)
    {
        if(pow(2,order) == element->size)// assumig we can use this, asked in PIAZZA already
        {
            // we are done
            break;
        }

        order++;
    }
    add_and_merge_buddies(element, order);

}

void seperate_buddies(MallocMetadata* element,int order, int size)
{
    if(order == 0)
    {
        return;
    }
    if((pow(2,order - 1) < size) && (size <= pow(2,order)))
    {
        // now we have order which fits the size,
        element->is_free = false;
        return;
    }
    else
    {
        // we have to split
        MallocMetadata* new_buddy; // how to create new object?
        new_buddy->size /= 2;
        add_and_merge_buddies(new_buddy, order - 1);
        element->size /= 2;
        seperate_buddies(element, order - 1, size);
    }

}

void remove_from_arr(MallocMetadata* element, int size)
{
    int order = 0;
    while(order < MAX_ORDER)
    {
        if(pow(2,order) == element->size)// assumig we can use this, asked in PIAZZA already
        {
            // we are done
            break;
        }

        order++;
    }
    seperate_buddies(element, order, size);
} 

//*********************************************************************************** FUNCS ************************************************************
MeList me_list = MeList(); //i don't think we need this here

void *smalloc(size_t size)
{
    if (size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }

    MallocMetadata *cur_node = me_list.dummy_head;
    for (int i = 0; i < me_list.length; i++)
    {
        if ((cur_node != NULL))
        {
            if (cur_node->is_free)
                if (size <= cur_node->size)
                {
                    cur_node->is_free = false;

                    // updating data
                    me_list.free_blocks--;
                    me_list.free_bytes -= cur_node->size; 
                    return (void *)((char *)cur_node + sizeof(MallocMetadata));
                }
            cur_node = cur_node->next;
        }
    }

    void *new_memory = sbrk(size + sizeof(MallocMetadata));
    if (new_memory == FAILED_SBRK_SYSCALL)
        return NULL;

    // update list data
    MallocMetadata *helper = (MallocMetadata *)new_memory;
    helper->size = size; 
    helper->is_free = false;
    me_list.append(helper);
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
    me_list.free_blocks++;
    me_list.free_bytes += ptr->size;
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
    return me_list.free_blocks;
}

size_t _num_free_bytes()
{
    return me_list.free_bytes;
}

size_t _num_allocated_blocks()
{
    return (size_t)me_list.length;
}

size_t _num_allocated_bytes()
{
    return me_list.allocated_bytes;
}

size_t _num_meta_data_bytes()
{
    return (size_t)(sizeof(MallocMetadata) * me_list.length);
}

size_t _size_meta_data()
{
    return (size_t)(sizeof(MallocMetadata));
}