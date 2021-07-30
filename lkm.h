#ifndef __LINUX_CLIQUE_H__
#define __LINUX_CLIQUE_H__


#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>



#define NTHREADS_SHIFT 5UL
#define NTHREADS (1 << NTHREADS_SHIFT)
#define SUBSCRIPT(x, y) (((x) << NTHREADS_SHIFT) + (y))
#define C_PRINT
#define VALID_ONLY

#define PID_HASH_BITS 14UL
#define PID_HASH_SIZE (1UL << PID_HASH_BITS)
#define MEM_HASH_BITS 26UL
#define MEM_HASH_SIZE (1UL << MEM_HASH_BITS)
#define PN(addr) ((addr) >> 12UL)

#define SCHED_CORE 0

#define C_IPI // whether use IPI


//#define C_USEMAX

#define C_ASSERT(v) 										\
	{ 																		\
		if (unlikely(!(v))) {								\
			printk(KERN_ERR "C_ASSERT failed in %s at %d", __FUNCTION__, __LINE__);\
		}																		\
	}

#define C_LOG(s)	\
	{\
		printk(KERN_ERR "C_LOG: %s, %s at %d", (s), __FUNCTION__, __LINE__);\
	}

struct clique {
    int pids[NTHREADS];
    int size;
    enum {
        C_VALID, C_REUSE, C_INVALID
    } flag;
};

struct mem_acc {
  short tids[2];
	unsigned long pn;
};

struct process_info {
	// for process-thread management
	char comm[TASK_COMM_LEN];
	atomic_t nthreads;
	int pids[NTHREADS];
	struct list_head list;

	// for memory accesses
	int matrix[NTHREADS * NTHREADS];
	struct mem_acc *mcs;
	int sum, last_sum;

	// for clique computation
	int scope;
	int cliques_size;
	struct clique cliques[NTHREADS];

	// for scheduling
	int pid_to_core[NTHREADS];
	int target_cliques;
};

struct c_thread_info {
	struct process_info *pi;
	short tid; // for indexing matrix
};

// args for smp_call_function_single
struct execution_arg {
	char *comm;
	int pid;
};

struct access_arg {
	int pid;
	unsigned long address;
};


extern struct c_thread_info thread_list[PID_HASH_SIZE];
extern struct process_info process_list;


// static inline
// void *resize(void *old, unsigned long old_size, unsigned long new_size) {
// 	void *ret = kmalloc(new_size, GFP_KERNEL);
// 	memcpy(ret, old, old_size);
// 	kfree(old);
// 	memset(ret + old_size, 0, new_size - old_size);
// 	return ret;
// }

void _insert_process(void *arg);

void _insert_thread(void *arg);

void _remove_thread(void *arg);

void _record_access(void *arg);

// called before insert_process & insert_thread
static inline
int check_name(char *comm) {
	int len = strlen(comm);
	if (unlikely(!strcmp(comm, "sysbench")))
		return 1;
	return 0;
}

static inline
void reset_process_info(struct process_info *pi) {
	C_ASSERT(pi);
	memset(pi->matrix, 0, sizeof(int) << (2 * NTHREADS_SHIFT));
	memset(pi->pids, -1, sizeof(pi->pids));
	memset(pi->mcs, -1, sizeof(struct mem_acc) << MEM_HASH_BITS);
	atomic_set(&pi->nthreads, 0);

#ifdef C_PRINT
	C_LOG(pi->comm);
#endif
}

static inline
struct process_info *search_process_info(char *comm) {
	struct process_info *pi = NULL;
	struct list_head *curr;
	
	list_for_each(curr, &process_list.list) {
		pi = list_entry(curr, struct process_info, list);
		if (!strcmp(pi->comm, comm)) {
			return pi;
		}
	}
	return NULL;
}

static inline
void insert_process(char *comm, int pid) {
	struct execution_arg *arg =
		(struct execution_arg *) kmalloc(sizeof(*arg), GFP_KERNEL);
	arg->comm = comm;
	arg->pid = pid;
	// kfree in _insert_process;

#ifdef C_IPI
	smp_call_function_single(SCHED_CORE, _insert_process,
		(void *) arg, 1);
#else
	_insert_process(arg);
#endif
}

static inline
void insert_thread(char *comm, int pid) {
	struct execution_arg *arg =
		(struct execution_arg *) kmalloc(sizeof(*arg), GFP_KERNEL);
	arg->comm = comm;
	arg->pid = pid;
	// kfree in _insert_thread;

#ifdef C_IPI
	smp_call_function_single(SCHED_CORE, _insert_thread,
		(void *) arg, 1);
#else
	_insert_thread(arg);
#endif
}

static inline
void remove_thread(char *comm, int pid) {
	struct execution_arg *arg =
		(struct execution_arg *) kmalloc(sizeof(*arg), GFP_KERNEL);
	arg->comm = comm;
	arg->pid = pid;
	// kfree in _remove_thread;

#ifdef C_IPI
	smp_call_function_single(SCHED_CORE, _remove_thread,
		(void *) arg, 1);
#else
	_remove_thread(arg);
#endif
}


static inline
int get_nshare(struct mem_acc *mc) {
  if (mc->tids[0] == -1) {
    if (mc->tids[1] == -1) {
      return 0;
    } else {
      return 1;
    }
  } else {
    if (mc->tids[1] == -1) {
      return 1;
    } else {
      return 2;
    }
  }
}

static inline
void inc_matrix(int *matrix, int x, int y) {
  ++matrix[SUBSCRIPT(x, y)];
  matrix[SUBSCRIPT(x, y)] = matrix[SUBSCRIPT(y, x)];
}

static inline
void record_access(int pid, unsigned long address) {
	struct access_arg *arg =
		(struct access_arg *) kmalloc(sizeof(*arg), GFP_KERNEL);
	arg->address = address;
	arg->pid = pid;
	// kfree in _record_access;

#ifdef C_IPI
	smp_call_function_single(SCHED_CORE, _record_access,
		(void *) arg, 1);
#else
	_record_access(arg);
#endif
}


#endif
