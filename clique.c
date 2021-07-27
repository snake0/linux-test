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

#include "clique.h"
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/smp.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/time.h>

// #define for_each_sibling(s, cpu) \
//     for_each_cpu(s, cpu_sibling_mask(cpu))
// #define for_each_core(s, cpu) \
//     for_each_cpu(s, cpu_core_mask(cpu))
// #define for_each_node_cpu(s, node) \
//     for_each_cpu(s, cpumask_of_node(node))

static int num_cpus = 0, 
    num_cores = 0, num_threads = 0;

static int num_nodes = 2, cores_per_node = 8;

struct c_thread_info thread_list[1UL << PID_HASH_BITS];
struct process_info process_list;


int *cpu_state = NULL;
int threads_chosen[NTHREADS];



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

// Processor topology
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

void init_scheduler(void) {
    // detect_topology();
    INIT_LIST_HEAD(&process_list.list);
    process_list.comm[0] = '\0';
    memset(thread_list, 0, sizeof(thread_list));
}

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

static
void set_affinity(int pid, int core) {
    struct cpumask mask;
    cpumask_clear(&mask);
    cpumask_set_cpu(core, &mask);
    sched_setaffinity(pid, &mask);
}

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
        printk("merge_clique: NULL pointer\n");
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
    struct clique *c2, *temp = pi->cliques;
    int distance = -1, temp_int;
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
    pi->scope = atomic_read(&pi->nthreads);
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

// void assign_cpus_for_clique(struct clique *c, int node) {
//     int cpu_curr = cores_per_node * node, size = c->size, *pids = c->pids, i;
//     for (i = 0; i < size; ++i) {
//         threads_chosen[pids[i]] = cpu_curr++;
//         if (cpu_curr == (node + 1) * cores_per_node) {
//             cpu_curr = cores_per_node * node;
//         }
//     }
// }

// void calculate_threads_chosen(void) {
//     int i, node = 0;
//     for (i = 0; i < NTHREADS; ++i) {
//         if (cliques[i].flag == C_VALID) {
//             assign_cpus_for_clique(cliques + i, node++);
//         }
//     }
// #ifdef C_PRINT
//     printk("Threads chosen:\n");
//     for (i = 0; i < NTHREADS; ++i) {
//         printk("%d -> %d\n", i, threads_chosen[i]);
//     }
// #endif
// }

void clique_analysis_process(struct process_info *pi) {
    struct clique *c1, *c2;
    
    init_cliques(pi);
    if (!strcmp("sysbench", pi->comm))
        init_matrix(pi->matrix);
    else
        init_random(pi->matrix);

#ifdef C_PRINT
    print_matrix(pi->matrix, pi->scope);
    print_cliques(pi);
#endif

    while (pi->cliques_size > num_nodes) {
        while (pi->cliques_size > 0) {
            c1 = get_first_valid(pi);
            c2 = find_neighbor(c1, pi);
            merge_clique(c1, c2, pi);
        }
        reset_cliques(pi);

#ifdef C_PRINT
        printk(KERN_ERR "cliques:");
        print_cliques(pi);
        printk(KERN_ERR "cliques_size: %d, with ", pi->cliques_size);
        print_clique_sizes(pi);
#endif
    }
    // calculate_threads_chosen();
}

void clique_analysis(void) {
    struct process_info *pi = NULL;
	struct list_head *curr;
	
	list_for_each(curr, &process_list.list) {
		pi = list_entry(curr, struct process_info, list);
		clique_analysis_process(pi);
	}
}

void f(void *data) {
    int a = (int) data;

}

int init_module(void) {
    struct timespec
    int i;

    for (i = 0; i < 16; ++i) {
        
    }

    for (i = 0; i < 10000; ++i) {
        smp_call_function_single(1, f, NULL, 0);
    }
    stop = jiffies;
    printk(KERN_ERR "%f", (double)(stop-start)/HZ);
    // int i;
    // init_scheduler();
    // insert_process("stress-ng", 1112);
    // for (i=1113;i<1113+30;++i) {
    //     insert_thread("stress-ng",i);
    // }

    // insert_process("sysbench", 1143);
    // for (i=1144;i<1144+30;++i) {
    //     insert_thread("sysbench",i);
    // }

    

    // print_processes();
    // clique_analysis();
    // exit_scheduler();
    return 0;
}

void cleanup_module(void) {}

MODULE_LICENSE("GPL");
