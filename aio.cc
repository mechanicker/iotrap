// -*-c++-*-
// Time-stamp: <2016-01-29 10:47:34 dky>
//-----------------------------------------------------------------------------
// File : aio
// Desc : aio -h
//-----------------------------------------------------------------------------
#ifndef _GNU_SOURCE
#define _GNU_SOURCE		/* syscall() is not POSIX */
#endif

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

#include <errno.h>
#include <stdio.h>		/* for perror() */
#include <unistd.h>		/* for syscall() */
#include <sys/syscall.h>	/* for __NR_* definitions */
#include <linux/aio_abi.h>	/* for AIO types and constants */

#ifdef UNIT_TEST
extern "C" {
    int io_setup(unsigned nr, aio_context_t *ctxp) __attribute__((weak));
    int io_destroy(aio_context_t ctx) __attribute__((weak));
    int io_submit(aio_context_t ctx, long nr,  struct iocb **iocbpp) __attribute__((weak));
    int io_getevents(aio_context_t ctx, long min_nr, long max_nr,
		     struct io_event *events, struct timespec *timeout) __attribute__((weak));
}
#else
inline int io_setup(unsigned nr, aio_context_t *ctxp)
{
    return syscall(__NR_io_setup, nr, ctxp);
}

inline int io_destroy(aio_context_t ctx)
{
    return syscall(__NR_io_destroy, ctx);
}

inline int io_submit(aio_context_t ctx, long nr,  struct iocb **iocbpp)
{
    return syscall(__NR_io_submit, ctx, nr, iocbpp);
}

inline int io_getevents(aio_context_t ctx, long min_nr, long max_nr,
			struct io_event *events, struct timespec *timeout)
{
    return syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
}
#endif

void
usage()
{
    fprintf(stderr, "usage: aio -f filename -s fileSize -b blockSize"
	    " -o read|write [-t thread|process] [-h]\n");
    fprintf(stderr, "       -f Name of the file to read or write\n");
    fprintf(stderr, "       -s File size (multiple of block size)"
	    " in bytes (10), mb (10m) or gb (10g)\n");
    fprintf(stderr, "       -b Block size in bytes (10), mb (10m)"
	    " or gb (10g)\n");
    fprintf(stderr, "       -o IO operation to perform on the file"
	    " [read|write]\n");
    fprintf(stderr, "       -t High resolution timer to use\n");
    fprintf(stderr, "       -h Display this help\n\n");
    return;
}

size_t
get_size(char *size_str)
{
    size_t size = 0;
    size_t len = strlen(size_str);

    switch (size_str[len - 1]) {
    case 'k':
    case 'K':
	size = 1024;
	break;
    case 'm':
    case 'M':
	size = 1024 * 1024;
	break;
    case 'g':
    case 'G':
	size = 1024 * 1024 * 1024;
	break;
    default:
	size = 1;
	break;
    }

    if (size > 1) {
	size_str[len - 1] = '\0';
    }
    size *= atoll(size_str);

    return size;
}

int main(int argc, char *argv[])
{
    clockid_t cid = CLOCK_THREAD_CPUTIME_ID;
    int err = 0;
    int ret = -1;

    int op = -1;
    size_t size = 0;
    size_t bsize = 0;
    char *file = NULL;
    size_t chunks = 0;
    size_t iterations = 1;

    // Parse the input arguments
    char c;
    while ((c = getopt (argc, argv, "s:f:o:b:t:i:h")) != -1) {
	switch (c)
	{
	case 's':
	    size = get_size(optarg);
	    break;
	case 'f':
	    file = optarg;
	    break;
	case 'i':
	    iterations = atoll(optarg);
	    if (0 == iterations) {
		fprintf(stderr, "Error: Invalid \"%s\" iterations specified\n",
			optarg);
		usage();
		return -EINVAL;
	    }
	    break;
	case 'o':
	    op = (strcasecmp("read", optarg) == 0) ? 0
		: (strcasecmp("write", optarg) == 0) ? 1 : -1;
	    if (-1 == op) {
		fprintf(stderr, "Error: Unrecognized IO operation \'%s\'\n",
			optarg);
		return -1;
	    }
	    break;
	case 'b':
	    bsize = get_size(optarg);
	    break;
	case 't':
	    cid = (strcasecmp("thread", optarg) == 0)
		? CLOCK_THREAD_CPUTIME_ID
		: (strcasecmp("process", optarg) == 0)
		? CLOCK_PROCESS_CPUTIME_ID : -1;
	    if (-1 == cid) {
		fprintf(stderr, "Error: Unrecognized timer specified \'%s\'\n",
			optarg);
		return -1;
	    }
	    break;

	case 'h':
	    usage();
	    return 0;
	case '?':
	    if (optopt == 'f' || optopt == 's' ||
		optopt == 'o' || optopt == 'b')
		fprintf (stderr, "Option -%c requires an argument.\n", optopt);

	    usage();
	    return -1;
	default:
	    break;
	}
    }

    if (NULL == file || 0 == size || bsize == 0 || op == -1) {
	fprintf(stderr, "Error: Insufficient arguments\n");
	usage();
	return -1;
    }

    if (bsize > size) {
	fprintf(stderr, "Error: Block size %lu cannot be greater"
		" than file size %lu\n", bsize, size);
	return -1;
    }

    // Ensure we have a file size that is a multiple of block size
    if (size % bsize) {
	fprintf(stderr, "Info: File size padded by %lu bytes to be"
		" a multiple of block size\n", (size % bsize));
	size += size % bsize;
    }

    // Compute the chunk size
    chunks = size/bsize;

    // Setup I/O control block
    struct iocb **cbs = (struct iocb **)calloc(chunks, sizeof(struct iocb *));
    if (NULL == cbs) {
	err = errno;
	perror("failed to allocate memory");
	return err;
    }

    // Allocate the data buffers and initialize it
    for (size_t cc = 0; cc < chunks; cc++) {
	cbs[cc] = (struct iocb *)malloc(sizeof(struct iocb));
	if (NULL == cbs[cc]) {
	    err = errno;
	    perror("failed to allocate memory");
	    return err;
	}
	memset(cbs[cc], 0, sizeof(struct iocb));

	cbs[cc]->aio_lio_opcode = (0 == op) ? IOCB_CMD_PREAD: IOCB_CMD_PWRITE;
	// Construct the data buffer
	char *data = (char *)malloc(bsize);
	if (NULL == data) {
	    err = errno;
	    perror("failed to allocate memory");
	    return err;
	}
	memset(data, (op == 0) ? '\0' : 'w', bsize);
	// Add new line to enable testing ops via 'wc'
	if (op == 1) {
	    data[bsize - 1] = '\n';
	}

	cbs[cc]->aio_buf = (size_t)data;
	cbs[cc]->aio_data = (size_t)data;

	cbs[cc]->aio_offset = (cc * bsize);
	cbs[cc]->aio_nbytes = bsize;
    }

    // Construct the events list
    struct io_event *events = (io_event *)malloc(chunks * sizeof(struct io_event));
    if (NULL == events) {
	err = errno;
	perror("failed to allocate memory");
	return err;
    }
    memset(events, 0, chunks * sizeof(struct io_event));

    aio_context_t ctx = {0};
    ret = io_setup(chunks, &ctx);
    if (ret < 0) {
	err = errno;
	perror("io_setup error");
	if (err == EAGAIN) {
	    fprintf(stderr, "Hint: consider increasing aio-max-nr via"
		    " \"sysctl -w fs.aio-max-nr=%lu\"\n", chunks);
	}
	return err;
    }

    fprintf(stdout, "%s file of size %lu in %lu chunks of block size %lu"
	    " in %lu iteration%c\n",
	    (op == 0) ? "Reading": "Writing",
	    size, chunks, bsize, iterations, (iterations > 1) ? 's' :' ');

    // Average throughput
    double throughput = 0.0;

    size_t iter = 0;
    do {
	// Track the time
	struct timespec stime = {0};
	struct timespec etime = {0};

	int fd = open(file, (( op == 0) ? O_RDONLY : O_WRONLY|O_TRUNC|O_CREAT)|
		      O_DIRECT|O_SYNC, 0664);
	if (fd < 0) {
	    err = errno;
	    perror("open error");
	    return err;
	}

	// Update the fd on all iocb
	for (size_t cc = 0; cc < chunks; cc++) {
	    cbs[cc]->aio_fildes = fd;
	}

	// Record the start time
	clock_gettime(cid, &stime);

	// ASYNC block read/write
	ret = io_submit(ctx, chunks, cbs);
	if (ret != (int)chunks) {
	    err = errno;
	    if (ret < 0)
		perror("io_submit error");
	    else
		fprintf(stderr, "could not sumbit IOs");
	    return  err;
	}

	// Get IO completion events
	size_t completion_events = 0;
	do {
	    ret = io_getevents(ctx, 1, (chunks - completion_events), events, NULL);
	    if (ret > 0) {
		completion_events += ret;
	    } else {
		perror("io_getevents error");
	    }
	} while (completion_events < chunks);

	// Record the start time
	clock_gettime(cid, &etime);
	close(fd);

	// Compute the throughput
	size_t dnsecs = (((etime.tv_sec * 1000000000) + etime.tv_nsec) -
			 ((stime.tv_sec * 1000000000) + stime.tv_nsec));
	double delta_secs = dnsecs/1000000000.0;
	double tp = ((size/(1024.0 * 1024.0))/delta_secs);

	// Compute the average throughput
	if (0 == iter) {
	    throughput = tp;
	} else {
	    throughput = (throughput + tp)/2.0;
	}

	// Printing average makes sense for multiple iterations
	if (iterations > 1) {
	    fprintf(stdout, "Throughput[%f]: %f mb/secs\n", throughput, tp);
	}
    } while (++iter < iterations);

    // Cleanup before exiting
    ret = io_destroy(ctx);
    if (ret < 0) {
	err = errno;
	perror("io_destroy error");
	return err;
    }

    // Free all the allocated resources
    for (size_t cc = 0; cc < chunks; cc++) {
	free((void *)cbs[cc]->aio_buf);
	free(cbs[cc]);
    }
    free(cbs);
    free(events);

    fprintf(stdout, "Throughput: %f mb/secs\n", throughput);

    return 0;
}