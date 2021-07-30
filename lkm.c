/*
 * Thread mapper using clique mapping algorithm.
 *
 * Group up threads that communicate the most into a ``clique``
 *
 * Copyright (C) 2021, Trusted Cloud Group, Shanghai Jiao Tong University.
 *
 * Authors:
 *   Xingguo Jia 	    <jiaxg1998@sjtu.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include "lkm.h"

#include <linux/compiler.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/sort.h>
#include <linux/random.h>

/*
#define for_each_sibling(s, cpu) \
    for_each_cpu(s, cpu_sibling_mask(cpu))
#define for_each_core(s, cpu) \
    for_each_cpu(s, cpu_core_mask(cpu))
#define for_each_node_cpu(s, node) \
    for_each_cpu(s, cpumask_of_node(node))

static int num_cpus = 0, 
    num_cores = 0, num_threads = 0;
static int num_nodes = 0, cores_per_node = 0;
*/

struct c_thread_info thread_list[1UL << PID_HASH_BITS];
struct process_info process_list;


int *cpu_state = NULL;
// int pi->pid_to_core[NTHREADS];


// communication rates between threads
int default_matrix[NTHREADS * NTHREADS] = {
    0,  12, 5,  3,  0,  1,  1,  1,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  1, 0, 0, 0, 1,  0,  0,  0,  0,  1,  0,  1,  4,  11,
    12, 0,  12, 2,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  1,  0,  1,  0, 
    5,  12, 0,  12, 1,  4,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  1,  1, 
    3,  2,  12, 0,  5,  1,  1,  1,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  1,  0,  0,  1,
    0,  0,  1,  5,  0,  10, 0,  1,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    1,  0,  4,  1,  10, 0,  15, 3,  1, 0,  2,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    1,  0,  0,  1,  0,  15, 0,  18, 0, 1,  1,  0,  0,  1,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    1,  0,  0,  1,  1,  3,  18, 0,  8, 3,  2,  2,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  1,  0,  8,  0, 6,  3,  2,  0,  0,  0, 1,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  1,  3,  6, 0,  12, 2,  1,  2,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  2,  1,  2,  3, 12, 0,  10, 1,  1,  0, 1,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  2,  2, 2,  10, 0,  8,  3,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 1,  1,  8,  0,  16, 1, 3,  3,  0,  1, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  1,  0,  0, 2,  1,  3,  16, 0,  6, 2,  3,  1,  0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  1,  6,  0, 8,  0,  0,  2, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  1, 0,  1,  0,  3,  2,  8, 0,  11, 1,  0, 0, 0, 1, 1,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  3,  3,  0, 11, 0,  12, 5, 1, 2, 0, 0,  0,  1,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  1,  0, 1,  12, 0,  9, 0, 1, 1, 1,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
    1,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  1,  0,  2, 0,  5,  9,  0, 7, 5, 0, 1,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  1,  0,  7, 0, 7, 1, 0,  0,  3,  0,  0,  0,  1,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  2,  1,  5, 7, 0, 9, 1,  2,  2,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 1,  0,  1,  0, 1, 9, 0, 8,  0,  2,  0,  0,  0,  0,  0,  0,  0, 
    1,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 1,  0,  1,  1, 0, 1, 8, 0,  10, 3,  0,  0,  0,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 2, 0, 10, 0,  14, 2,  0,  1,  0,  0,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  1,  0,  0, 3, 2, 2, 3,  14, 0,  12, 0,  1,  2,  2,  0,  2, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  2,  12, 0,  16, 2,  2,  2,  0,  0, 
    0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  16, 0,  5,  1,  1,  0,  0, 
    1,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  1,  1,  2,  5,  0,  10, 4,  4,  1, 
    0,  1,  0,  1,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 1, 0, 0, 0,  0,  2,  2,  1,  10, 0,  10, 1,  1, 
    1,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  2,  2,  1,  4,  10, 0,  15, 2, 
    4,  1,  1,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  0,  0,  0,  4,  1,  15, 0,  13, 
    11, 0,  1,  1,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0, 0,  0,  0,  0, 0, 0, 0, 0,  0,  2,  0,  0,  1,  1,  2,  13, 0
};

// static void detect_topology(void) {
//   int node, cpu, core, thread;
//   if (num_nodes)
//     return;

//   for_each_online_node(node) {
//     ++num_nodes;
//     for_each_node_cpu(cpu, node) {
//       ++num_cpus;
//       for_each_core(core, cpu) {
//         ++num_cores;
//         for_each_sibling(thread, core) {
//           ++num_threads;
//         }
//       }
//     }
//   }
// #ifdef C_PRINT
//   printk(KERN_INFO
//            "topology: %d nodes, %d cpus, %d cores, %d threads",
//            num_nodes, num_cpus, num_cores, num_threads);
// #endif
//   cores_per_node = num_threads / num_nodes;
// }

void _insert_process(void *arg) {
    struct execution_arg *a = (struct execution_arg *) arg;
    char *comm = a->comm;
    int pid = a->pid;
    struct process_info *pi = search_process_info(comm);
	int h;

    kfree(arg);
	
	// reuse process_info, to avoid kfree/kmalloc
	if (pi) {
		if (atomic_read(&pi->nthreads)) {
			// must call reset_process_info before reusing
			C_ASSERT(0);
			printk(KERN_ERR "Duplicate process %s, %d", comm, pid);
			return;
		} else {
			// successful reuse
			printk("Reusing process %s, %d", comm, pid);
			atomic_set(&pi->nthreads, 1);
			pi->pids[0] = pid;
			h = hash_32(pid, PID_HASH_BITS);
			C_ASSERT(thread_list[h].pi == NULL);
			thread_list[h].pi = pi;
			thread_list[h].tid = 0;
			return;
		}
	}

	// cannot reuse and need allocate
	pi = (struct process_info *)
		kmalloc(sizeof(struct process_info), GFP_KERNEL);
	C_ASSERT(pi != NULL);

	// process/thread info
	strcpy(pi->comm, comm);
	atomic_set(&pi->nthreads, 1);
	memset(pi->matrix, 0, sizeof(pi->matrix));
	memset(pi->pids, -1, sizeof(pi->pids));
	
	// linked list
	pi->pids[0] = pid;
	INIT_LIST_HEAD(&pi->list);
	list_add(&pi->list, &process_list.list);

	// find process_info fast with pid
	h = hash_32(pid, PID_HASH_BITS);
	C_ASSERT(thread_list[h].pi == NULL);
	thread_list[h].pi = pi;
	thread_list[h].tid = 0;

	// use vmalloc for large data block
	pi->mcs = (struct mem_acc *) vmalloc(sizeof(struct mem_acc) << MEM_HASH_BITS);
	C_ASSERT(pi->mcs);
	memset(pi->mcs, -1, sizeof(struct mem_acc) << MEM_HASH_BITS);

	pi->last_sum = 0;

	memset(pi->pid_to_core, -1, sizeof(pi->pid_to_core));

#ifdef C_PRINT
	C_LOG(comm);
#endif
}

void _insert_thread(void *arg) {
    struct execution_arg *a = (struct execution_arg *) arg;
    char *comm = a->comm;
    int pid = a->pid;
    int h = hash_32(pid, PID_HASH_BITS);
	short tid;
	struct process_info *pi = search_process_info(comm);

    kfree(arg);

	// threads must be inserted after process
	if (!pi) {
		C_ASSERT(pi != NULL);
		printk(KERN_ERR "No process %s, %d", comm, pid);
		return;
	}

	// thread_list is hash-based. Collision is possible
	if (thread_list[h].pi) {
		C_ASSERT(thread_list[h].pi == NULL);
		printk("Thread hash collision %s, %d", comm, pid);
		return;
	}

	// thread_list maps from ``hash(pid)`` to ``process_info & tid``
	thread_list[h].pi = pi;
	tid = atomic_inc_return(&pi->nthreads) - 1;

	pi->pids[tid] = pid;
	thread_list[h].tid = tid;

#ifdef C_PRINT
	C_LOG(comm);
#endif
}

void _remove_thread(void *arg) {
    struct execution_arg *a = (struct execution_arg *) arg;
    char *comm = a->comm;
    int pid = a->pid;
    int h = hash_32(pid, PID_HASH_BITS);
	short tid;
	struct process_info *pi = NULL;
	struct list_head *curr;

    kfree(arg);
	
	list_for_each(curr, &process_list.list) {
		pi = list_entry(curr, struct process_info, list);
		if (!strcmp(pi->comm, comm)) {
			break;
		}
	}

	if (!pi) {
		C_ASSERT(pi);
		printk(KERN_ERR "No process %s, %d", comm, pid);
		return;
	}
	if (!thread_list[h].pi) {
		C_ASSERT(thread_list[h].pi);
		printk(KERN_ERR "No process info %s, %d", comm, pid);
		return;
	}
	
	thread_list[h].pi = NULL;
	thread_list[h].tid = -1;

	tid = atomic_dec_return(&pi->nthreads);
	if (unlikely(tid == 0)) {
		reset_process_info(pi);
	}

#ifdef C_PRINT
	C_LOG(comm);
#endif
} 

void _record_access(void *arg) {
  struct access_arg *a = (struct access_arg *) arg;
  unsigned long address = a->address;
  int pid = a->pid;
  int h = hash_32(pid, PID_HASH_BITS);
  struct process_info *pi = thread_list[h].pi;
  short tid = thread_list[h].tid;
  struct mem_acc *mc;

  kfree(arg);

  if (likely(!pi)) {
    return;
  }

  mc = &pi->mcs[hash_32(PN(address), MEM_HASH_BITS)];

  switch(get_nshare(mc)) {
    case 0: {
      mc->tids[0] = tid;
			mc->pn = PN(address);
      break;
    }

    case 1: {
			if (unlikely(mc->pn != PN(address))) {
				C_ASSERT(0);
				printk(KERN_ERR "Address collision");
				return;
			}

      if (mc->tids[0] != tid) {
        mc->tids[1] = mc->tids[0];
        mc->tids[0] = tid;
        inc_matrix(pi->matrix, tid, mc->tids[1]);
      }
      break;
    }

    case 2: {
			if (unlikely(mc->pn != PN(address))) {
				C_ASSERT(0);
				printk(KERN_ERR "Address collision");
				return;
			}

      if (mc->tids[0] != tid) {
        if (mc->tids[1] != tid) {
          inc_matrix(pi->matrix, tid, mc->tids[0]);
          inc_matrix(pi->matrix, tid, mc->tids[1]);
        } else {
          inc_matrix(pi->matrix, tid, mc->tids[0]);
          mc->tids[1] = mc->tids[0];
          mc->tids[0] = tid;
        }
      } else if (mc->tids[1] != tid) {
        inc_matrix(pi->matrix, tid, mc->tids[1]);
      }
    }
  } 
}

static int num_cores = 0, num_nodes = 0, cores_per_node = 0;

// Processor topology
static void detect_topology(void) {
  num_cores = num_online_cpus();
  cores_per_node = nr_cpus_node(0);
  num_nodes = num_cores / cores_per_node;
  printk(KERN_ERR "num_cores %d," 
                  "cores_per_node %d,"
                  "num_nodes %d",
                   num_cores,
                   cores_per_node,
                   num_nodes);
}

// only in scheduling thread
void init_scheduler(void) {
    INIT_LIST_HEAD(&process_list.list);
    process_list.comm[0] = '\0';
    memset(thread_list, 0, sizeof(thread_list));
}

// only in scheduling thread
void exit_scheduler(void) {
    // we do cleanup here
    struct process_info *pi;
	struct list_head *curr, *q;
    list_for_each_safe(curr, q, &process_list.list) {
        pi = list_entry(curr, struct process_info, list);
        printk(KERN_ERR "Process %s exit", pi->comm);
        vfree(pi->mcs);
        list_del(&pi->list);
        kfree(pi);
    }
}

// static
// void set_affinity(int pid, int core) {
//     struct cpumask mask;

//     if (unlikely(core == -1)) {
//         return;
//     }

//     cpumask_clear(&mask);
//     cpumask_set_cpu(core, &mask);
//     sched_setaffinity(pid, &mask);
// }

#ifdef C_PRINT

static void print_matrix(int *k, int size) {
    int i, j;
    printk(KERN_ERR "------[ matrix ]------\n");
    for (i = 0; i < size; ++i) {
        for (j = 0; j < size; ++j) {
            printk(KERN_CONT "%2d ", k[SUBSCRIPT(i, j)]);
        }
        printk(KERN_CONT "\n");
    }
}

static void print_array(int *k, int size) {
    int i;
    printk(KERN_ERR "------[ array ]------\n");
    for (i = 0; i < size; ++i) {
        printk(KERN_CONT "%2d ", k[i]);
    }
    printk(KERN_CONT "\n");
}

static void print_clique_sizes(struct process_info *pi) {
    int i;
    struct clique *cliques = pi->cliques;

    for (i = 0; i < pi->scope; ++i) {
        if (cliques[i].flag == C_VALID) {
            printk(KERN_CONT "%d ", cliques[i].size);
        }
    }
    printk(KERN_CONT"\n");
}

int print_clique(struct clique *c) {
    int j;
#ifdef VALID_ONLY
    if (c->flag == C_VALID) {
        printk(KERN_ERR "{");
        for (j = 0; j < c->size; ++j) {
            printk(KERN_CONT "%d ", c->pids[j]);
        }
        printk(KERN_CONT "}");
        return 0;
    }
    return -1;
#endif
    switch (c->flag) {
        case C_VALID:
            printk("VALID ");
            break;
        case C_REUSE:
            printk("REUSE ");
            break;
        case C_INVALID:
            printk("INVALID ");
            break;
    }
    printk("{");
    for (j = 0; j < c->size; ++j) {
        printk("%d ", c->pids[j]);
    }
    printk("}");
    return 0;
}

void print_cliques(struct process_info *pi) {
    int i, r;
    printk(KERN_ERR "-------------------------------------------------------\n");
    printk("Process %s clique analysis", pi->comm);
    for (i = 0; i < pi->scope; ++i) {
        r = print_clique(pi->cliques + i);
        if (r == 0) {
            printk(KERN_CONT"\n");
        }
    }
}

void print_processes(void) {
    struct process_info *pi;
	struct list_head *curr;
    int n;

    printk(KERN_ERR "print_processes: start");
    list_for_each(curr, &process_list.list) {
        pi = list_entry(curr, struct process_info, list);
        printk(KERN_ERR "print_processes: Process %s", pi->comm);
        n = atomic_read(&pi->nthreads);
        if (n) {
            printk(KERN_ERR "print_processes: Threads of %s", pi->comm);
            print_array(pi->pids, n);
            // printk(KERN_ERR "Matrix of %s", pi->comm);
            // print_matrix(pi->matrix, n);
        } else {
            printk(KERN_ERR "print_processes: Empty process %s", pi->comm);
        }
    }
    printk(KERN_ERR "print_processes: end");
}

#endif // C_PRINT

int clique_distance(struct clique *c1, struct clique *c2, int *matrix) {
    int ret = 0, i, j;
    if (c1 && c2) {
#ifndef C_USEMAX
        for (i = 0; i < c1->size; ++i) {
            for (j = 0; j < c2->size; ++j) {
                ret += matrix[SUBSCRIPT(c1->pids[i], c2->pids[j])];
            }
        }
#else
        for (i = 0; i < c1->size; ++i) {
            for (j = 0; j < c2->size; ++j) {
                if (ret < matrix[SUBSCRIPT(c1->pids[i], c2->pids[j])]) {
                    ret = matrix[SUBSCRIPT(c1->pids[i], c2->pids[j])];
                }
            }
        }
#endif
    } else {
        printk("clique_distance: NULL pointer\n");
        ret = -1;
    }
    return ret;
}

void merge_clique(struct clique *c1, struct clique *c2, struct process_info *pi) {
    if (c1 && c2) {
#ifdef C_PRINT
        printk("Merging: ");
        print_clique(c1);
        print_clique(c2);
#endif
        if (c1->flag != C_VALID) {
            if (c2->flag == C_VALID) {
                c2->flag = C_REUSE;
                pi->cliques_size--;
            }
        } else {
            if (c2->flag != C_VALID) {
                c1->flag = C_REUSE;
                pi->cliques_size--;
            } else {
                memcpy(c1->pids + c1->size, c2->pids, sizeof(int) * c2->size);
                c1->size = c1->size + c2->size;
                c1->flag = C_REUSE;
                c2->flag = C_INVALID;
                pi->cliques_size -= 2;
            }
        }
    } else {
        if (c1 && c1->flag == C_VALID) {
#ifdef C_PRINT
            printk("Merging: ");
            print_clique(c1);
#endif
            c1->flag = C_REUSE;
            pi->cliques_size--;
        } else if (c2 && c2->flag == C_VALID) {
#ifdef C_PRINT
            printk("Merging: ");
            print_clique(c2);
#endif
            c2->flag = C_REUSE;
            pi->cliques_size--;
        } else {
            C_LOG("both NULL pointer");
        }
    }
}

struct clique *get_first_valid(struct process_info *pi) {
    struct clique *ret = pi->cliques;
    while (ret->flag != C_VALID) {
        ret++;
        if (ret == pi->cliques + pi->scope) {
            printk("get_first_valid: NO valid clique\n");
            return NULL;
        }
    }
    return ret;
}

struct clique *find_neighbor(struct clique *c1, struct process_info *pi) {
    struct clique *c2 = NULL, *temp = pi->cliques;
    int distance = -1, temp_int;

    if (unlikely(pi->cliques_size == 1)) {
        return NULL;
    }

    while (temp < pi->cliques + pi->scope) {
        if (temp != c1 && temp->flag == C_VALID) {
            temp_int = clique_distance(c1, temp, pi->matrix);
            if (temp_int > distance) {
                distance = temp_int;
                c2 = temp;
            }
        }
        temp++;
    }
    return c2;
}

void reset_cliques(struct process_info *pi) {
    struct clique *temp = pi->cliques;
    while (temp < pi->cliques + pi->scope) {
        if (temp->flag == C_REUSE) {
            temp->flag = C_VALID;
            ++(pi->cliques_size);
        }
        temp++;
    }
}

void init_cliques(struct process_info *pi) {
    int i;
    struct clique *cliques = pi->cliques;
    pi->cliques_size = pi->scope;
    for (i = 0; i < pi->scope; ++i) {
        cliques[i].pids[0] = i;
        cliques[i].size = 1;
        cliques[i].flag = C_VALID;
    }
}

void init_matrix(int *matrix) {
    memcpy(matrix, default_matrix, sizeof(default_matrix));
}

void init_random(int *matrix) {
    int i, j;
    for (i = 0; i < NTHREADS; ++i) {
        for (j = 0; j < i; ++j) {
            matrix[SUBSCRIPT(i, j)] = (int) (get_random_int() & 0x7fffffff) % 100;
        }
    }
    for (i = 0; i < NTHREADS; ++i) {
        for (j = i; j < NTHREADS; ++j) {
            matrix[SUBSCRIPT(i, j)] = matrix[SUBSCRIPT(j, i)];
        }
    }
}

int sum_process_matrix(struct process_info *pi) {
    int ret = 0, i, j;
    for (i = 0; i < pi->scope; ++i) {
        for (j = 0; j < i; ++j) {
            ret += pi->matrix[SUBSCRIPT(i, j)];
        }
    }
    return ret;
}

void assign_cpus_for_clique(struct clique *c, int node, struct process_info *pi) {
    int cpu_curr = cores_per_node * node, size = c->size, *pids = c->pids, i;
    for (i = 0; i < size; ++i) {
        pi->pid_to_core[pids[i]] = cpu_curr++;
        if (cpu_curr == (node + 1) * cores_per_node) {
            cpu_curr = cores_per_node * node;
        }
    }
}

void calculate_threads_chosen(struct process_info *pi) {
    int i, node = 0;
    struct clique *cliques = pi->cliques;
    for (i = 0; i < pi->scope; ++i) {
        if (cliques[i].flag == C_VALID) {
            assign_cpus_for_clique(cliques + i, node++, pi);
        }
    }
#ifdef C_PRINT
    printk("Threads chosen:\n");
    for (i = 0; i < pi->scope; ++i) {
        printk("%d -> %d -> %d\n", i, pi->pids[i], pi->pid_to_core[i]);
    }
#endif
}

void clique_analysis_process(struct process_info *pi) {
    struct clique *c1, *c2;
    init_cliques(pi);

#ifdef C_PRINT
    print_cliques(pi);
#endif

    while (pi->cliques_size > pi->target_cliques) {
        while (pi->cliques_size > 0) {
            c1 = get_first_valid(pi);
            c2 = find_neighbor(c1, pi);
            merge_clique(c1, c2, pi);
        }
        reset_cliques(pi);
               

#ifdef C_PRINT
        // printk(KERN_ERR "cliques:");
        // print_cliques(pi);
        // printk(KERN_ERR "cliques_size: %d, with ", pi->cliques_size);
        // print_clique_sizes(pi);
#endif
    }
}

void set_affinity_process(struct process_info *pi) {
    struct cpumask mask;
    int i;

    for (i = 0; i < pi->scope; ++i) {
        cpumask_clear(&mask);
        cpumask_set_cpu(pi->pid_to_core[i], &mask);
        sched_setaffinity(pi->pids[i], &mask);
    }
#ifdef C_PRINT
    C_LOG("Set affinity process done");
#endif
}

// main scheduler thread
static int balancer_func(void *v) {
    int sleep_time = 1000;
    struct process_info *pi = NULL;
	struct list_head *curr;
    int total_threads, matrix_diff;

    init_scheduler();

#ifdef C_PRINT
    printk(KERN_ERR "CLIQUE thread is up");
#endif
    msleep_interruptible(sleep_time);
    num_nodes = 4;
    // while (!kthread_should_stop()) {
        set_current_state(TASK_INTERRUPTIBLE);

        total_threads = 0;
        list_for_each(curr, &process_list.list) {
            pi = list_entry(curr, struct process_info, list);
            init_matrix(pi->matrix);
            pi->scope = atomic_read(&pi->nthreads);
            pi->sum = sum_process_matrix(pi);
            matrix_diff = pi->sum - pi->last_sum;
#ifdef C_PRINT
            printk(KERN_ERR "Matrix of Process %s with diff %d",
                pi->comm, matrix_diff);
            print_matrix(pi->matrix, pi->scope);
#endif
            pi->last_sum = pi->sum;
            
            if (matrix_diff > 100) {
                clique_analysis_process(pi);
                calculate_threads_chosen(pi);
            }
        }

        list_for_each(curr, &process_list.list) {
            pi = list_entry(curr, struct process_info, list);
            pi->target_cliques = num_nodes * pi->scope / total_threads;
#ifdef C_PRINT
            printk(KERN_ERR "Target cliques: Process %s get %d cliques", pi->comm, pi->target_cliques);
#endif
        }

        msleep_interruptible(sleep_time);
    // }

    exit_scheduler();
    return 0;
}

static int test_func(void *v) {
    int i;
    insert_process("stress-ng", 1112);
    for (i=1113;i<1113+31;++i) {
        insert_thread("stress-ng",i);
    }
    insert_process("sysbench", 1144);
    for (i=1145;i<1145+31;++i) {
        insert_thread("sysbench",i);
    }
    return 0;
}

// static int f1(void *v) {
//     for (;;) {
//         msleep(10);
//     }
//     return 0;
// }

// static int f2(void *v) {
//     while (!kthread_should_stop()) {
//         msleep_interruptible(100);
//     }
//     return 0;
// }

// static int f3(void *v) {
//     while (!kthread_should_stop()) {
//         msleep_interruptible(1000);
//     }
//     return 0;
// }

static struct task_struct *balancer = NULL;

static struct task_struct *kthread_run_on_cpu(int (*threadfn)(void *data),
					  void *data,
					  unsigned int cpu,
					  const char *namefmt) {
    struct task_struct *ret = kthread_create_on_node(
            threadfn, NULL, cpu_to_node(cpu), namefmt);
    kthread_bind(ret, cpu);
    wake_up_process(ret);
    return ret;
}

int __init init_clique_scheduler(void) {
    detect_topology();

#ifdef C_PRINT
    printk(KERN_ERR "CLIQUE init!");
#endif
    if (!balancer) {
        balancer = kthread_run_on_cpu(balancer_func, NULL, SCHED_CORE, "clique-balancer");
    }
    kthread_run_on_cpu(test_func, NULL, 3, "test");

    return 0;
}



void __exit cleanup_clique_scheduler(void) {
    if (balancer) {
        kthread_stop(balancer);
        balancer = NULL;
#ifdef C_PRINT
        printk(KERN_ERR "CLIQUE thread is down");
#endif
    }
}

module_init(init_clique_scheduler);
module_exit(cleanup_clique_scheduler);
MODULE_AUTHOR("Xingguo Jia <jiaxg1998@sjtu.edu.cn>");
MODULE_DESCRIPTION("CLIQUE Scheduler as a Driver");
MODULE_LICENSE("GPL");

