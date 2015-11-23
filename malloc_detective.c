/*
 * Malloc Detective: Core
 *
 * ---------------------------------------------------------------------------
 * Copyright (c) 2015 Ayumu Koujiya
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the 
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <execinfo.h>
#include <errno.h>

static void* (*origin_malloc)(size_t);
static void  (*origin_free)(void*);
static void* (*origin_libc_malloc)(size_t);
static void  (*origin_libc_free)(void*);
static int malloc_wapper_logfd = -1;
static int is_out_free_bt = 0;
/* depth: Flag of reentrace */
static __thread int depth;

static const char* INNER_FLAG_LOGFD        = "__LOGFD_FLAG_MALLOC_DETECTIVE";
static const char* MALLOC_DETECTIVE_OUTPUT = "MALLOC_DETECTIVE_OUTPUT";
static const char* MALLOC_DETECTIVE_CHILD  = "MALLOC_DETECTIVE_CHILD";
static const char* MALLOC_DETECTIVE_FREE   = "MALLOC_DETECTIVE_FREE";

#define MAX_BACKTRACE_SIZE 256
#define MAX_MESSAGE_SIZE PIPE_BUF

/* ---------------------------- 
 * Initialize
 * ---------------------------- */

static void load_malloc()
{
    origin_malloc = (void*(*)(size_t)) dlsym(RTLD_NEXT, "malloc");
}

static void load_free()
{
    origin_free = (void(*)(void*)) dlsym(RTLD_NEXT, "free");
}

static void load_libc_malloc()
{
    origin_libc_malloc = (void*(*)(size_t)) dlsym(RTLD_NEXT, "__libc_malloc");
}

static void load_libc_free()
{
    origin_libc_free = (void(*)(void*)) dlsym(RTLD_NEXT, "__libc_free");
}

/* Initializer of each process */
void __attribute__((constructor)) init_malloc_wrapper()
{
    const char* malloc_detective_free = getenv(MALLOC_DETECTIVE_FREE);
    is_out_free_bt = (malloc_detective_free && atoi(malloc_detective_free) == 1);

    /* INNER_FLAG_UP: Logging file descriptor for child-processes. */
    const char* inner_flag_logfd = getenv(INNER_FLAG_LOGFD);
    char* output_name = NULL;

    /* MALLOC_DETECTIVE_CHILD: Reuse flag of log stream by children. */
    const char* malloc_detective_child = getenv(MALLOC_DETECTIVE_CHILD);
    const int is_reuse = (malloc_detective_child && atoi(malloc_detective_child) == 1);

    /* Get file discriptor for output log */
    malloc_wapper_logfd = STDERR_FILENO;
    if (inner_flag_logfd) {
        /* Reuse the file descriptor that parent has generated.
         * (or -1. Output suppressed by parents) */
        malloc_wapper_logfd = atoi(inner_flag_logfd);
    } else if ((output_name = getenv(MALLOC_DETECTIVE_OUTPUT)) != NULL) {
        /* Deciding output stream, stderr or fifo.
         *   Using fifo if defined env-value MALLOC_DETECTIVE_OUTPUT. */
        struct stat filestat;
        if (stat(output_name, &filestat) == -1) {
            /* Creating fifo, if not exists */
            if (mkfifo(output_name, 0600) == -1) {
                const char* errstr = strerror(errno);
                fprintf(stderr, "Error: Can't create fifo(%s). mkfifo:%s\n", output_name, errstr);
                _exit(2);
            }
        } else if (!S_ISFIFO(filestat.st_mode)) {
            fprintf(stderr, "Error: %s is not fifo.\n", output_name);
            _exit(3);
        }
        const mode_t openflag = O_WRONLY || (is_reuse ? 0 : O_CLOEXEC);
        malloc_wapper_logfd = open(output_name, openflag);
        if (malloc_wapper_logfd < 0) {
            const char* errstr = strerror(errno);
            fprintf(stderr, "Error: Can't open fifo(%s). open:%s\n", output_name, errstr);
            _exit(1);
        }

        /* Save output stream if defined MALLOC_DETECTIVE_CHILD environment as 1. 
         * Otherwise save -1 to suppress output by children. */
        if (is_reuse) {
            char str_logfd[32] = {0};
            sprintf(str_logfd, "%d", malloc_wapper_logfd);
            setenv(INNER_FLAG_LOGFD, str_logfd, 1);
        } else {
            setenv(INNER_FLAG_LOGFD, "-1", 1);
        }
    }

    /* load libc's malloc/free */
    load_malloc();
    load_free();
    load_libc_malloc();
    load_libc_free();
}

/* ---------------------------- 
 * Output log string functions
 * ---------------------------- */

static void log_output(
    int is_trace,
    int (*head_build)(char*,size_t,const void*,size_t),
    void* addr, size_t size)
{
    char msg[MAX_MESSAGE_SIZE];
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);

    int msgsize = strftime(msg, sizeof(msg), "%Y-%m-%dT%H:%M:%S", localtime_r(&tv.tv_sec, &tm));
    msgsize += sprintf(&msg[msgsize], ".%06d\t", (int)tv.tv_usec);
    msgsize += head_build(&msg[msgsize], sizeof(msg) - msgsize, addr, size);

    if (is_trace) {
        void* trace[MAX_BACKTRACE_SIZE];
        memset(trace, 0, sizeof(trace));
        const int num_bt = backtrace(trace, MAX_BACKTRACE_SIZE);
        char** const trace_str = backtrace_symbols(trace, MAX_BACKTRACE_SIZE);
        int i;

        for (i = 2/*remove this module*/; i < num_bt; ++i) {
            const size_t btstrsize = strlen(trace_str[i]);
            if (MAX_MESSAGE_SIZE < (btstrsize + msgsize))  {
                break;
            }
            strncat(msg, "\t", 1);
            strncat(msg, trace_str[i], btstrsize);
            msgsize += btstrsize + 1;
        }
        if (trace_str) {
            origin_free(trace_str);
        }
    }

    strncat(msg, "\n", 1);
    ++msgsize;

    write(malloc_wapper_logfd, msg, msgsize);
}

static int loghead_build_malloc(char* str, size_t str_size, const void* addr, size_t size)
{
    return snprintf(str, str_size, "%d\tmalloc\t0x%08lx\t%zu", getpid(), (unsigned long)addr, size);
}

static int loghead_build_free(char* str, size_t str_size, const void* addr, size_t size)
{
    return snprintf(str, str_size, "%d\tfree\t0x%08lx\t0", getpid(), (unsigned long)addr);
}

static int loghead_build_libc_malloc(char* str, size_t str_size, const void* addr, size_t size)
{
    return snprintf(str, str_size, "%d\tmalloc\t0x%08lx\t%zu", getpid(), (unsigned long)addr, size);
}

static int loghead_build_libc_free(char* str, size_t str_size, const void* addr, size_t size)
{
    return snprintf(str, str_size, "%d\tfree\t0x%08lx\t0", getpid(), (unsigned long)addr);
}

/* ---------------------------- 
 * Wrappers
 * ---------------------------- */

void* malloc(size_t size)
{
    if (!origin_malloc) {
        load_malloc();
    }

    void* result = origin_malloc(size);
    if (depth > 0|| malloc_wapper_logfd == -1) {
        return result;
    }

    ++depth;
    log_output(1, &loghead_build_malloc, result, size);
    --depth;

    return result;
}

void free(void* p)
{
    if (!origin_free) {
        load_free();
    }

    origin_free(p);
    if (depth > 0|| malloc_wapper_logfd == -1) {
        return;
    }

    ++depth;
    log_output(is_out_free_bt, &loghead_build_free, p, 0);
    --depth;
}

void* __libc_malloc(size_t size)
{
    if (!origin_libc_malloc) {
        load_libc_malloc();
    }

    void* result = origin_libc_malloc(size);
    if (depth > 0|| malloc_wapper_logfd == -1) {
        return result;
    }

    ++depth;
    log_output(1, &loghead_build_libc_malloc, result, size);
    --depth;

    return result;
}

void __libc_free(void* p)
{
    if (!origin_libc_free) {
        load_libc_free();
    }

    origin_libc_free(p);
    if (depth > 0|| malloc_wapper_logfd == -1) {
        return;
    }

    ++depth;
    log_output(is_out_free_bt, &loghead_build_libc_free, p, 0);
    --depth;
}

/* vim: ts=4 sts=4 sw=4 expandtab :
 */
