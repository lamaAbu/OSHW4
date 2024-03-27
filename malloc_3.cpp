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
        element->prev_free = dummy_head;
        allocated_bytes += element->size;
        length++;
        return;
    }
    for (int i = 0; i < length - 1; i++)
        current_node = current_node->next_free;

    current_node->next_free = element;
    element->prev_free = current_node;
    allocated_bytes += element->size;
    length++;
}

void MeList::add_node_by_adress_free(MallocMetadata *new_node)
{
    MallocMetadata *tmp = dummy_head;
    for (int i = 0; i < length; i++)
    {
        if (tmp->address > new_node->address)
            break;
        tmp = tmp->next_free;
    }
    tmp->prev_free = new_node;
    new_node->next_free = tmp;
    length++;
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
        length--;
    }
}

MallocMetadata *MeList::remove_head_free()
{
    if (dummy_head == NULL)
    {
        return NULL;
    }
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
        element->prev = dummy_head;
        allocated_bytes += element->size;
        length++;
        return;
    }
    for (int i = 0; i < length - 1; i++)
        current_node = current_node->next;

    current_node->next = element;
    element->prev = current_node;
    allocated_bytes += element->size;
    length++;
}

void MeList::add_node_after_element_all(MallocMetadata *element, MallocMetadata *new_node)
{
    MallocMetadata *next = element->next;
    if (next)
        next->prev = new_node;
    new_node->next = next;
    new_node->prev = element;
    element->next = new_node;
    length++;
}

//************************************************************* helper functions ************************************************************

MeList *free_blocks_arr[MAX_ORDER + 1];
MeList *all_blocks_list;
MeList *mmap_list;

void init_blocks(void *source_address)
{
    for (int i = 0; i < INITIAL_BLOCKS_NUM; i++)
    {
        MallocMetadata *element = (MallocMetadata *)((char *)source_address + (i * MAX_SIZE));
        element->size = MAX_SIZE - sizeof(MallocMetadata);
        element->is_free = true;
        element->next = NULL;
        element->prev = NULL;
        element->next_free = NULL;
        element->prev_free = NULL;
        element->address = i * MAX_SIZE;
        all_blocks_list->append_all(element);
        free_blocks_arr[MAX_ORDER]->append_free(element);
    }
}

MallocMetadata *init_buddy(MallocMetadata *element)
{
    int virtual_adress = (int)(element->address + element->size + sizeof(MallocMetadata));
    char *physical_adress = (char *)all_blocks_list->dummy_head + virtual_adress;
    MallocMetadata *buddy_of_element = (MallocMetadata *)physical_adress;
    buddy_of_element->address = virtual_adress;
    buddy_of_element->size = element->size;
    buddy_of_element->is_free = true;
    return buddy_of_element;
}

//--------------------------------------------------------------------------------------------------------------------
//                                          merge part
//--------------------------------------------------------------------------------------------------------------------

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

            if (next_node->size != node_in_all->size)
                return NULL;

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
            if (prev_node->size != node_in_all->size)
                return NULL;

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
        return;
    
    else
    {
        MallocMetadata *father = merge_all(element);
        if (father != NULL)
        {
            free_blocks_arr[order]->delete_node_from_free(father);
            free_blocks_arr[order]->delete_node_from_free(father->next_free);
            free_blocks_arr[order + 1]->add_node_by_adress_free(father);
            add_and_merge_buddies(father, order + 1);
        }
    }
}

void check_merge(MallocMetadata *element) // approved
{
    int order = 0;
    while (order < MAX_ORDER)
    {
        if ((pow(2, order) * 128) == (int)(element->size + sizeof(MallocMetadata)))
            break;

        order++;
    }
    add_and_merge_buddies(element, order);
}

//--------------------------------------------------------------------------------------------------------------------
//                                          split part
//--------------------------------------------------------------------------------------------------------------------

// returns buddy_of_element so i can add it to all_blocks_list
MallocMetadata *split_free(MallocMetadata *element, int order) // 3
{
    // removing from order
    free_blocks_arr[order]->delete_node_from_free(element);

    // adding to order - 1
    element->size = (element->size - sizeof(MallocMetadata)) / 2;
    MallocMetadata *buddy_of_element = init_buddy(element);
    free_blocks_arr[order - 1]->add_node_by_adress_free(element);
    free_blocks_arr[order - 1]->add_node_by_adress_free(buddy_of_element);
    return buddy_of_element;
}

// this function should find for me what is the specific order
// there might be case that in the very first order we get here has empty list in free_arr
// so we should go to order+1 and check if there is nodes there
MallocMetadata *find_specific_order(int order, size_t data_size) // 2
{
    if (order > 10)
        return NULL;

    // we have to split
    MallocMetadata *element = free_blocks_arr[order]->remove_head_free();
    if (element == NULL)
        find_specific_order(order + 1, data_size);

    // found the specific order
    else
    {
        while (order >= 0)
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
                all_blocks_list->add_node_after_element_all(element, buddy);
                order--;
            }
        }
        return NULL;
    }
}

// assume that outer function calls this func
// it give it data_size and expects from it to return the most prefect node
// definition most prefect :
// the smallest node with size that can fit data_size , and smallest in adress
// and in the way of finiding that node we have to do splits
MallocMetadata *find_prefect_node(size_t data_size) // 1
{
    int order = 0;
    while (order < MAX_ORDER)
    {
        if ((pow(2, order) * 128) >= (int)(data_size + sizeof(MallocMetadata)))
            break;

        order++;
    }
    return find_specific_order(order, data_size);
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
    me_list.append_free(helper);
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