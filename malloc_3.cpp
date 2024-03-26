// Part 3 - Better Malloc
//  Implementing by Buddy Allocator

// SIZE DOES NOT INCLUDE SIZE OF MallocMetadata !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// we calculate address according to node place in all_block_list
//  0 < address < 31 * 128
//  (order-1) * 128 <= address of each node < order * 128
//  splitting node to node1 and node2
//  node1->adress = (order-1) * 128
//  node2-> address = ((order-1) * 128) + (father.size / 2)
//  each one of the node1 and node2 has size of (father.size - sizeof(MallocMetadata))/2

// merging nodes
// merged_node.address = left_son.address
// merged_node.size = left_son.size + right_son.size + sizeof(MallocMetadata)

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
    size_t size; // doesn't include metadata of cur node
    bool is_free;
    int address;
    MallocMetadata *next;
    MallocMetadata *prev;
    MallocMetadata *father;
    MallocMetadata *next_free;
    MallocMetadata *prev_free;
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
    void add_node_free(MallocMetadata *new_node);
    void delete_node(MeList *list, MallocMetadata *node);
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

void MeList::add_node_free(MallocMetadata *new_node)
{
    MallocMetadata* tmp = dummy_head;
    for(int i=0; i < length; i++)
    {
        if(tmp->address > new_node->address)
            break;
        tmp = tmp->next_free;
    }
    tmp->prev_free = new_node;
    new_node->next_free = tmp;
    length++;
}

void MeList::remove_head()
{
    if (dummy_head == nullptr)
    {
        return;
    }
    else
    {
        MallocMetadata *tmp = dummy_head;
        if (tmp->next != nullptr)
        {
            dummy_head = tmp->next;
            dummy_head->prev = nullptr;
        }
    }
}

//*********************************************************************************** Histogram ************************************************************

MeList *free_blocks_arr[MAX_ORDER + 1]; // should we initialize it?
MeList *all_blocks_list;                // each elemnt is a tree "reveresed tree"
MeList *mmap_list;

void init_blocks()
{
    for (int i = 0; i < INITIAL_BLOCKS_NUM; i++)
    {
        MallocMetadata *element;
        element->size = MAX_SIZE;
        element->is_free = true;
        element->father = NULL;
        element->next = NULL;
        element->prev = NULL;
        element->address = i * MAX_SIZE;
        all_blocks_list->append(element);
    }
}

MallocMetadata *find_block(int order)
{
    MallocMetadata *helper = all_blocks_list->dummy_head;
    while (order != 0)
        helper = helper->next;
    return helper;
}

void add_and_merge_buddies(MallocMetadata *element, int order) // recursion approved
{

    if (order == MAX_ORDER)
    {
        return;
    }
    else
    {
        // we should merge
        MallocMetadata *check = merge_all(element);
        if (check != nullptr)
        {
            merge_free(element, check, order);
            free_blocks_arr[2*order]->add_node_free();
            add_and_merge_buddies(element->father, 2 * order);
        }
    }
}

void merge_free(MallocMetadata *node_in_free, MallocMetadata *buddy_node, int order) // good
{
    MeList *cur_list = free_blocks_arr[order];
    MallocMetadata *cur_node = cur_list->dummy_head;
    for (int i = 0; i < cur_list->length; i++)
    {
        if (cur_node == node_in_free)
        {
            if (node_in_free->next_free)
            {
                if (node_in_free->next_free == buddy_node)
                {
                    if (buddy_node->next_free)
                        buddy_node->next_free->prev_free = node_in_free->prev_free;
                }
                else
                node_in_free->next_free->prev_free = buddy_node->prev_free;
            }
            if (node_in_free->prev)
            {
                if (node_in_free->prev_free == buddy_node)
                {
                    if (buddy_node->prev_free)
                        buddy_node->prev_free->next_free = node_in_free->next_free;
                }
                else
                node_in_free->prev_free->next_free = buddy_node->next_free;
            }
            break;
        }
        cur_node = cur_node->next;
    }
    cur_list->length -=2;
}

MallocMetadata *merge_all(MallocMetadata *node_in_all) // approved
{
    MallocMetadata *next_node = node_in_all->next;
    MallocMetadata *prev_node = node_in_all->prev;
    MallocMetadata *father = node_in_all->father;
    if (next_node != NULL)
    { // merge with next
        if (father == next_node->father && next_node->is_free)
        {
            // we have to merge with the next
            if (node_in_all->prev != NULL)
            {
                node_in_all->prev->next = father;
            }
            if (next_node->next != NULL)
            {
                next_node->next->prev = father;
            }
            father->prev = node_in_all->prev;
            father->next = next_node->next;
            father->size = node_in_all->size * 2 + sizeof(MallocMetadata);
            return next_node;
        }
    }
    else if (prev_node != NULL)
    {
        if (father == prev_node->father && prev_node->is_free)
        {
            // we have to merge with the prev
            if (node_in_all->next != NULL)
            {
                node_in_all->next->prev = father;
            }
            if (prev_node->prev != NULL)
            {
                prev_node->prev->next = father;
            }
            father->next = node_in_all->next;
            father->prev = prev_node->prev;
            father->size = prev_node->size * 2 + sizeof(MallocMetadata);
            return prev_node;
        }
    }
    return NULL;
}

void add_to_arr(MallocMetadata *element)
{
    int order = 0;
    while (order < MAX_ORDER)
    {
        if (pow(2, order) == element->size) // assumig we can use this, asked in PIAZZA already
        {
            // we are done
            break;
        }

        order++;
    }
    add_and_merge_buddies(element, order);
}

void split_buddies(MallocMetadata *element, int order, int size)
{
    if (order == 0)
    {
        return;
    }
    if ((pow(2, order - 1) < size) && (size <= pow(2, order)))
    {
        // now we have order which fits the size,
        element->is_free = false;
        return;
    }
    else
    {
        // we have to split
        MallocMetadata *new_buddy; // how to create new object?
        new_buddy->size /= 2;
        add_and_merge_buddies(new_buddy, order - 1);
        element->size /= 2;
        split_buddies(element, order - 1, size);
    }
}
void split_free(int order)
{
}

MallocMetadata *slpit_all()
{
}

void remove_from_arr(MallocMetadata *element, int size)
{
    int order = 0;
    while (order < MAX_ORDER)
    {
        if (pow(2, order) == element->size) // assumig we can use this, asked in PIAZZA already
        {
            // we are done
            break;
        }

        order++;
    }
    seperate_buddies(element, order, size);
}

//*********************************************************************************** FUNCS ************************************************************
MeList me_list = MeList(); // i don't think we need this here

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