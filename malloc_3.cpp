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
    void append(MallocMetadata *element);
    void add_node_by_adress(MallocMetadata *new_node);
    void add_node_all(MallocMetadata *new_node);
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

void MeList::add_node_by_adress(MallocMetadata *new_node)
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

void MeList::remove_head()
{
    if (dummy_head == NULL)
    {
        return;
    }
    else
    {
        MallocMetadata *tmp = dummy_head;
        if (tmp->next != NULL)
        {
            dummy_head = tmp->next;
            dummy_head->prev = NULL;
        }
    }
}

//*********************************************************************************** Histogram ************************************************************

MeList *free_blocks_arr[MAX_ORDER + 1]; // should we initialize it?
MeList *all_blocks_list;                // each elemnt is a tree "reveresed tree"
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
        all_blocks_list->append(element);
        free_blocks_arr[MAX_ORDER]->append(element);
    }
}

MallocMetadata *find_prefect_node(int order)
{
    MallocMetadata *helper = all_blocks_list->dummy_head;
    while (order != 0)
        helper = helper->next;
    return helper;
}

//--------------------------------------------------------------------------------------------------------------------
//                                          merge part
//--------------------------------------------------------------------------------------------------------------------

void add_and_merge_buddies(MallocMetadata *element, int order) // recursion approved
{

    if (order == MAX_ORDER)
    {
        return;
    }
    else
    {
        // we should merge
        MallocMetadata *father = merge_all(element);
        if (father != NULL)
        {
            // by father here .. i just want to get adress of the left buddy
            merge_free(father, order);
            free_blocks_arr[order + 1]->add_node_by_adress(father);
            add_and_merge_buddies(father, order + 1);
        }
    }
}

void merge_free(MallocMetadata *node_in_free, int order) // approved
{
    MeList *cur_list = free_blocks_arr[order];
    MallocMetadata *cur_node = cur_list->dummy_head;
    for (int i = 0; i < cur_list->length; i++)
    {
        if (cur_node == node_in_free)
        {
            // this is always the case (next / prev might be NULL)
            // prev -> cur_node -> buddy_node -> next

            // this always exist, node_in_free has always the smaller address
            // buddy_node = cur_node->next_free
            MallocMetadata *next = cur_node->next_free->next_free;
            MallocMetadata *prev = cur_node->prev_free;
            if (next)
                next->prev_free = prev;
            if (prev)
                prev->next_free = next;
            if ((next == NULL) && (prev == NULL))
                cur_list->dummy_head = NULL;
            break;
        }
        cur_node = cur_node->next;
    }
    cur_list->length -= 2;
}

// either returns "father" or NULL
MallocMetadata *merge_all(MallocMetadata *node_in_all) // approved
{
    MallocMetadata *next_node = node_in_all->next;
    MallocMetadata *prev_node = node_in_all->prev;
    int xor_result = node_in_all->address ^ ((int)(node_in_all->size + sizeof(MallocMetadata)));
    if (next_node != NULL)
    {
        // note about xor is at the beginning
        if (xor_result == next_node->address && next_node->is_free)
        {

            // if "buddies" are not same size they are not buddies
            if (next_node->size != node_in_all->size)
                return NULL;

            // note there was another if like that, previously it should point at father
            // but notice that node_in_all's meta data is excatly father's metadata
            // so there is no mean to point at node_in_all's father bcs it's himself
            if (next_node->next != NULL)
            {
                next_node->next->prev = node_in_all;
            }

            node_in_all->next = next_node->next;
            node_in_all->size = node_in_all->size * 2 + sizeof(MallocMetadata);

            // i want to return the "father"
            return node_in_all;
        }
    }
    else if (prev_node != NULL)
    {
        if (xor_result == prev_node->address && prev_node->is_free)
        {
            if (prev_node->size != node_in_all->size)
                return NULL;

            if (node_in_all->next != NULL)
            {
                node_in_all->next->prev = prev_node;
            }

            prev_node->next = node_in_all->next;
            prev_node->size = prev_node->size * 2 + sizeof(MallocMetadata);
            return prev_node;
        }
    }
    return NULL;
}

void check_merge(MallocMetadata *element) // approved
{
    int order = 0;
    while (order < MAX_ORDER)
    {
        if ((pow(2, order) * 128) == (int)(element->size + sizeof(MallocMetadata))) // assumig we can use this, asked in PIAZZA already
        {
            // we are done
            break;
        }

        order++;
    }
    add_and_merge_buddies(element, order);
}

//--------------------------------------------------------------------------------------------------------------------
//                                          split part
//--------------------------------------------------------------------------------------------------------------------

void split_all(MallocMetadata *element, MallocMetadata *buddy_of_element)// 5
{
    MallocMetadata *cur_node = all_blocks_list->dummy_head;
    for (int i = 0; i < all_blocks_list->length; i++)
    {
        if (cur_node == element)
        {
            MallocMetadata *next = cur_node->next_free;
            if (next)
                next->prev = buddy_of_element;
            buddy_of_element->next = next;
            buddy_of_element->prev = cur_node;
            cur_node->next = buddy_of_element;
            break;
        }
        cur_node = cur_node->next;
    }
    all_blocks_list->length++;
}

// returns buddy_of_element so i can add it to all_blocks_list
MallocMetadata *split_free(MallocMetadata *element, int order)// 4
{
    MeList *cur_list = free_blocks_arr[order];
    MallocMetadata *cur_node = cur_list->dummy_head;
    for (int i = 0; i < cur_list->length; i++)
    {
        if (cur_node == element)
        {
            // removing from order
            MallocMetadata *next = cur_node->next_free;
            MallocMetadata *prev = cur_node->prev_free;
            if (next)
                next->prev_free = prev;
            if (prev)
                prev->next_free = next;
            if ((next == NULL) && (prev == NULL))
                cur_list->dummy_head = NULL;
            cur_list->length--;

            // adding to order - 1
            element->size = (element->size - sizeof(MallocMetadata)) / 2;
            //(char*)all_blocks_list->dummy_head) this is the actual physical address
            MallocMetadata *buddy_of_element = (MallocMetadata *)((char *)all_blocks_list->dummy_head + element->address + element->size + sizeof(MallocMetadata));
            buddy_of_element->address = (int)(element->address + element->size + sizeof(MallocMetadata));
            buddy_of_element->size = element->size;
            buddy_of_element->is_free = true;
            free_blocks_arr[order - 1]->add_node_by_adress(element);
            free_blocks_arr[order - 1]->add_node_by_adress(buddy_of_element);
            return buddy_of_element;
        }
        cur_node = cur_node->next;
    }
    return NULL;
}

//chechs if in that order there is nodes or it's empty
MallocMetadata *find_free_node(int order, size_t data_size)// 3
{
    MeList *cur_list = free_blocks_arr[order];
    if (cur_list->length == 0)
        return NULL;

    MallocMetadata *to_return = cur_list->dummy_head;
    return to_return;
}

// this function should find for me what is the specific order
// there might be case that in the very first order we get here has empty list in free_arr
// so we should go to order+1 and check if there is nodes there
MallocMetadata *find_specific_order(int order, size_t data_size)// 2
{
    if (order > 10)
    {
        return NULL;
    }
    // we have to split
    MallocMetadata *element = find_free_node(order, data_size);
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
                split_all(element, buddy);
                order--;
            }
        }
    }
}


// assume that outer function calls this func 
// it give it data_size and expects from it to return the most prefect node
// definition most prefect : 
// the smallest node with size that can fit data_size , and smallest in adress
// and in the way of finiding that node we have to do splits
MallocMetadata *find_prefect_node(size_t data_size)// 1
{
    int order = 0;
    while (order < MAX_ORDER)
    {
        if ((pow(2, order) * 128) >= (int)(data_size + sizeof(MallocMetadata)))
        {
            // we are done
            break;
        }

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