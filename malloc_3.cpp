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

// muth to find buddies :
// XOR(node1.adress, node1.size) == node2.adress ? if yes they are buddies.. else not ☻

#include <unistd.h>
#include <string.h>
#include <cmath>
#include <sys/mman.h>

#define MAX_ORDER 10
#define KILO_BYTE 1024
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

    // free methods
    void append_free(MallocMetadata *element);
    void add_node_by_adress_free(MallocMetadata *new_node);
    void delete_node_from_free(MallocMetadata *node);
    MallocMetadata *remove_head_free();

    // all methods
    void append_all(MallocMetadata *element);
    void add_node_after_element_all(MallocMetadata *element, MallocMetadata *new_node);

    void check_free_list(MallocMetadata *element);
    void append_free_list(MallocMetadata *element);
};

MeList::MeList() : length(0), free_blocks(0), free_bytes(0), allocated_bytes(0)
{
    dummy_head = NULL;
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ FREE METHODS @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

void MeList::append_free(MallocMetadata *element)
{
    MallocMetadata *current_node = dummy_head;
    if (current_node == NULL)
    {
        dummy_head = element;
        element->prev_free = NULL;

        return;
    }
    for (int i = 0; i < length - 1; i++)
        current_node = current_node->next_free;

    current_node->next_free = element;
    element->prev_free = current_node;
}

void MeList::add_node_by_adress_free(MallocMetadata *new_node)
{
    MallocMetadata *tmp = dummy_head;
    if (length == 0)
    {
        dummy_head = new_node;
        new_node->prev_free = NULL;
        return;
    }
    for (int i = 0; i < length; i++)
    {
        if (tmp->address > new_node->address)
            break;
        tmp = tmp->next_free;
    }
    tmp->prev_free = new_node;
    new_node->next_free = tmp;
}

void MeList::delete_node_from_free(MallocMetadata *node)
{
    if (node != NULL)
    {
        MallocMetadata *next_node = node->next_free;
        MallocMetadata *prev_node = node->prev_free;
        if (next_node)
            next_node->prev_free = prev_node;
        if (prev_node)
            prev_node->next_free = next_node;
        if ((next_node == NULL) && (prev_node == NULL))
            dummy_head = NULL;
    }
}

MallocMetadata *MeList::remove_head_free()
{
    if (dummy_head == NULL)
        return NULL;

    else
    {
        MallocMetadata *tmp = dummy_head;
        if (tmp->next_free != NULL)
            dummy_head = tmp->next_free;
        return tmp;
    }
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ ALL METHODS @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

void MeList::append_all(MallocMetadata *element)
{
    MallocMetadata *current_node = dummy_head;
    if (current_node == NULL)
    {
        dummy_head = element;
        element->prev = NULL;
        return;
    }
    for (int i = 0; i < length - 1; i++)
        current_node = current_node->next;

    current_node->next = element;
    element->prev = current_node;
}

void MeList::add_node_after_element_all(MallocMetadata *element, MallocMetadata *new_node)
{
    MallocMetadata *next = element->next;
    if (next)
        next->prev = new_node;
    new_node->next = next;
    new_node->prev = element;
    element->next = new_node;
}

void MeList::check_free_list(MallocMetadata *element)
{
    MallocMetadata *current_node = dummy_head;
    if (current_node == NULL)
        return;
    for (int i = 0; i < length - 1; i++)
    {
        if (current_node->address == element)
            break;
        current_node = current_node->next;
    }
    if (current_node->address == element)
    {
        if (current_node->size > element->size)
        {
            int virtual_adress = (int)(current_node->address + element->size + sizeof(MallocMetadata));
            char *physical_adress = (char *)all_blocks_list.dummy_head + virtual_adress;
            MallocMetadata *new_node = (MallocMetadata *)physical_adress;
            new_node->is_free = true;
            new_node->size = current_node->size - (element->size + sizeof(MallocMetadata));
            free_blocks++;
            //append new node;
        }
        MallocMetadata *next_node = node->next;
        MallocMetadata *prev_node = node->prev;
        if (next_node)
            next_node->prev = prev_node;
        if (prev_node)
            prev_node->next = next_node;
        if ((next_node == NULL) && (prev_node == NULL))
            dummy_head = NULL;
        free_blocks--;
    }
}

void MeList::append_free_list(MallocMetadata *element)
{

}

//************************************************************* helper functions ************************************************************

MeList free_blocks_arr[MAX_ORDER + 1];
MeList all_blocks_list;
MeList free_list;
MeList mmap_list;
int all_allocations = 0;

void init_blocks(void *source_address)
{
    for (int i = 0; i < INITIAL_BLOCKS_NUM; i++)
    {
        MallocMetadata *element = (MallocMetadata *)((char *)source_address + (i * BLOCK_SIZE));
        element->size = BLOCK_SIZE - sizeof(MallocMetadata);
        element->is_free = true;
        element->next = NULL;
        element->prev = NULL;
        element->next_free = NULL;
        element->prev_free = NULL;
        element->address = i * BLOCK_SIZE;
        all_blocks_list.append_all(element);
        free_blocks_arr[MAX_ORDER].append_free(element);
    }
}

MallocMetadata *init_buddy(MallocMetadata *element)
{
    int virtual_adress = (int)(element->address + element->size + sizeof(MallocMetadata));
    char *physical_adress = (char *)all_blocks_list.dummy_head + virtual_adress;
    MallocMetadata *buddy_of_element = (MallocMetadata *)physical_adress;
    buddy_of_element->address = virtual_adress;
    buddy_of_element->size = element->size;
    buddy_of_element->is_free = true;
    buddy_of_element->next = NULL;
    buddy_of_element->prev = NULL;
    buddy_of_element->next_free = NULL;
    buddy_of_element->prev_free = NULL;
    return buddy_of_element;
}

void *malloc_mmap(size_t size)
{
    void *new_memory = mmap(NULL, sizeof(MallocMetadata) + size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_memory == MAP_FAILED)
        return NULL;
    MallocMetadata *node = (MallocMetadata *)new_memory;
    node->address = 0;
    node->size = size;
    node->is_free = false;
    node->next = NULL;
    node->prev = NULL;
    node->next_free = NULL;
    node->prev_free = NULL;
    mmap_list.allocated_bytes += size;
    mmap_list.length++;
    mmap_list.append_all(node);
    return new_memory;
}

void free_mmap(MallocMetadata *node)
{
    mmap_list.length--;
    mmap_list.allocated_bytes -= node->size;
    munmap(node, sizeof(MallocMetadata) + node->size);
}

int order_calc(size_t size)
{
    int order = 0;
    while (order < MAX_ORDER)
    {
        if ((pow(2, order) * 128) >= (int)(size + sizeof(MallocMetadata)))
            break;

        order++;
    }
    return order;
}

//--------------------------------------------------------------------------------------------------------------------
//                                          merge part
//--------------------------------------------------------------------------------------------------------------------

void calc_merge(MallocMetadata *node, size_t *virtual_size, size_t actual_size)
{
    int xor_result = node->address ^ ((int)(*virtual_size + sizeof(MallocMetadata)));
    char *physical_adress = (char *)all_blocks_list.dummy_head + xor_result;
    MallocMetadata *buddy = (MallocMetadata *)physical_adress;
    if (buddy->is_free)
    {
        *virtual_size = buddy->size * 2 + sizeof(MallocMetadata);
        if (node->address > buddy->address)
            node = buddy;
        if (*virtual_size >= actual_size)
            return;
        calc_merge(node, virtual_size, actual_size);
    }
}

// either returns "father" or NULL
MallocMetadata *merge_all(MallocMetadata *node_in_all) // approved
{
    MallocMetadata *next_node = node_in_all->next;
    MallocMetadata *prev_node = node_in_all->prev;
    int xor_result = node_in_all->address ^ ((int)(node_in_all->size + sizeof(MallocMetadata)));
    if (next_node != NULL)
    {
        if ((xor_result == next_node->address) && next_node->is_free)
        {
            if (next_node->next != NULL)
                next_node->next->prev = node_in_all;

            node_in_all->next = next_node->next;
            node_in_all->size = node_in_all->size * 2 + sizeof(MallocMetadata);
            return node_in_all;
        }
    }
    else if (prev_node != NULL)
    {
        if ((xor_result == prev_node->address) && prev_node->is_free)
        {
            if (node_in_all->next != NULL)
                node_in_all->next->prev = prev_node;

            prev_node->next = node_in_all->next;
            prev_node->size = prev_node->size * 2 + sizeof(MallocMetadata);
            return prev_node;
        }
    }
    return NULL;
}

void add_and_merge_buddies(MallocMetadata *element, int order) // recursion approved
{

    if (order == MAX_ORDER)
    {
        all_allocations++;
        return;
    }

    else
    {
        MallocMetadata *father = merge_all(element);
        if (father != NULL)
        {
            free_blocks_arr[order].delete_node_from_free(father);
            free_blocks_arr[order].delete_node_from_free(father->next_free);
            free_blocks_arr[order + 1].add_node_by_adress_free(father);
            all_blocks_list.length--;
            add_and_merge_buddies(father, order + 1);
        }
    }
}

void check_merge(MallocMetadata *element) // approved
{
    int order = order_calc(element->size);
    add_and_merge_buddies(element, order);
}

//--------------------------------------------------------------------------------------------------------------------
//                                          split part
//--------------------------------------------------------------------------------------------------------------------

// returns buddy_of_element so i can add it to all_blocks_list
MallocMetadata *split_free(MallocMetadata *element, int order) // 3
{
    // removing from order
    free_blocks_arr[order].delete_node_from_free(element);

    // adding to order - 1
    element->size = (element->size - sizeof(MallocMetadata)) / 2;
    MallocMetadata *buddy_of_element = init_buddy(element);
    free_blocks_arr[order - 1].add_node_by_adress_free(element);
    free_blocks_arr[order - 1].add_node_by_adress_free(buddy_of_element);
    return buddy_of_element;
}

MallocMetadata *splitter(MallocMetadata *element, int order, size_t data_size)
{
    while (order > 0)
    {
        size_t half_size = (element->size - sizeof(MallocMetadata)) / 2;

        // reached to the maximum splits he can
        if (data_size > half_size)
        {
            element->is_free = false;
            return element;
        }
        else
        {
            MallocMetadata *buddy = split_free(element, order);
            if (buddy == NULL)
                return NULL;
            all_blocks_list.add_node_after_element_all(element, buddy);
            all_blocks_list.length++;
            order--;
        }
    }
    element->is_free = false;
    return element;
}

// this function should find for me what is the specific order
// there might be case that in the very first order we get here has empty list in free_arr
// so we should go to order+1 and check if there is nodes there
MallocMetadata *find_specific_order(int order, size_t data_size) // 2
{
    while (order <= MAX_ORDER)
    {
        MallocMetadata *element = free_blocks_arr[order].remove_head_free();
        if (element != NULL)
            return splitter(element, order, data_size);
        order++;
    }
    return NULL;
}

// assume that outer function calls this func
// it give it data_size and expects from it to return the most prefect node
// definition most prefect :
// the smallest node with size that can fit data_size , and smallest in adress
// and in the way of finiding that node we have to do splits
MallocMetadata *find_prefect_node(size_t data_size) // 1
{
    int order = order_calc(data_size);
    return find_specific_order(order, data_size);
}

//************************************************************ FUNCS ************************************************************
void *smalloc(size_t size)
{
    if (size == 0)
        return NULL;

    // mmap
    if (size >= BLOCK_SIZE)
    {
        void *new_memory = malloc_mmap(size);
        return (void *)((char *)new_memory + sizeof(MallocMetadata));
    }

    // blocks
    if (all_blocks_list.length == 0)
    {
        void *new_memory = sbrk(BLOCK_SIZE * INITIAL_BLOCKS_NUM);
        if (new_memory == FAILED_SBRK_SYSCALL)
            return NULL;
        init_blocks(new_memory);
    }
    MallocMetadata *node = find_prefect_node(size);
    if (node == NULL)
        return NULL;

    // num of free blocks is updated in find_prefect_node
    all_allocations++;
    all_blocks_list.allocated_bytes += size;
    return (void *)((char *)node + sizeof(MallocMetadata));
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

    // mmap
    if (ptr->size >= BLOCK_SIZE)
    {
        free_mmap(ptr);
        return;
    }

    // blocks
    ptr->is_free = true;
    all_blocks_list.free_bytes += ptr->size;
    all_allocations--;
    check_merge(ptr);
}

// You should use std::memmove for copying data in srealloc().
void *srealloc(void *oldp, size_t size)
{
    if (size == 0)
        return NULL;

    else if (!(oldp))
        return smalloc(size);

    MallocMetadata *oldPtr = (MallocMetadata *)((char *)oldp - sizeof(MallocMetadata));
    if (size <= oldPtr->size)
        return oldp;

    // check if maybe we can merge blocks
    if (size < BLOCK_SIZE)
    {
        MallocMetadata *helper = (MallocMetadata *)((char *)oldp - sizeof(MallocMetadata));
        size_t merge_size = 0;
        calc_merge(helper, &merge_size, size);
        if (merge_size >= size)
        {
            MallocMetadata *merged = (MallocMetadata *)((char *)oldp - sizeof(MallocMetadata));
            check_merge(merged);
            int order = order_calc(size);
            MallocMetadata *node = splitter(helper, order, size);
            void *put_data = (void *)((char *)node + sizeof(MallocMetadata));
            memmove(put_data, oldp, size);
            sfree(oldp);
            return put_data;
        }
    }

    // this is for both mmap case and "not enough merges" blocks case
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
    return all_blocks_list.free_blocks;
}

size_t _num_free_bytes()
{
    return all_blocks_list.free_bytes;
}

size_t _num_allocated_blocks()
{
    return (size_t)(all_allocations + mmap_list.length);
}

size_t _num_allocated_bytes()
{
    return all_blocks_list.allocated_bytes + mmap_list.allocated_bytes;
}

size_t _num_meta_data_bytes()
{
    int all = all_allocations + mmap_list.length;
    return (size_t)(sizeof(MallocMetadata) * all);
}

size_t _size_meta_data()
{
    return (size_t)(sizeof(MallocMetadata));
}
