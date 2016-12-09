//-*-c++-*-
// Time-stamp: <2016-02-01 09:04:58 dky>
//-----------------------------------------------------------------------------
//  Generic library function hooking infrastructure
//  Usage: LD_PRELOAD=./iotrap.so sample_program
//-----------------------------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#if 0
}
#endif
#endif

#define _XOPEN_SOURCE 500
#include <unistd.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>
#include <sys/syscall.h>
#include <dlfcn.h>

// For intercepting POSIX calls
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/resource.h>

// For intercepting AIO calls
#ifndef __USE_XOPEN2K8
#define __USE_XOPEN2K8
#endif
#include <aio.h>
#include <linux/aio_abi.h>

#ifdef _POSIX_HOOK_SRC
#define FUNC_PTR(ret, func, args) static ret (*func##_orig)args = 0
#else
#define FUNC_PTR(ret, func, args) ret (*func##_orig)args
#endif
#define DLSYM_FUNC_PTR(func) func##_orig = (typeof(func##_orig))dlsym(RTLD_NEXT, #func); assert(func##_orig)

#include <pthread.h>
bool iotrap_trace = false;
unsigned long int iotrap_fiji = 0;

static pthread_once_t posix_hook_initialized = PTHREAD_ONCE_INIT;
#ifndef NDEBUG
#define IOTRAP_TRACE(op) do {			\
	if (iotrap_trace) {			\
	    (op);				\
	}					\
    } while(0)
#else
#define IOTRAP_TRACE(op)
#endif

#define POSIX_HOOK_INIT() do {						\
	(void)pthread_once(&posix_hook_initialized, posix_hook_init);	\
	IOTRAP_TRACE(fprintf(stderr, "iotrap trace: %s\n", __FUNCTION__)); \
    } while(0)

// LD_PRELOAD based hook for POSIX functions
FUNC_PTR(int,		creat, (const char *pathname, mode_t mode));
FUNC_PTR(int,		open, (const char *pathname, int flags, ...));
FUNC_PTR(int,		open64, (const char *pathname, int flags, ...));
FUNC_PTR(int,		close, (int fd));
FUNC_PTR(FILE *,	fdopen, (int fd, const char *mode));
FUNC_PTR(ssize_t,	read, (int fd, void *buf, size_t count));
FUNC_PTR(ssize_t,	write, (int fd, const void *buf, size_t count));

FUNC_PTR(int,		dup, (int oldfd));
FUNC_PTR(int,		dup2, (int oldfd, int newfd));

FUNC_PTR(FILE *,	fopen, (const char *path, const char *mode));
FUNC_PTR(int,		fclose, (FILE *fp));

FUNC_PTR(int,		fcntl, (int fd, int cmd, ...));

FUNC_PTR(int,		fsync, (int fd));

FUNC_PTR(ssize_t,	pread, (int fd, void *buf, size_t count, off_t offset));
FUNC_PTR(ssize_t,	pwrite, (int fd, const void *buf, size_t count, off_t offset));
FUNC_PTR(ssize_t,	readv, (int fd, const struct iovec *iov, int iovcnt));
FUNC_PTR(ssize_t,	writev, (int fd, const struct iovec *iov, int iovcnt));
FUNC_PTR(ssize_t,	preadv, (int fd, const struct iovec *iov, int iovcnt, off_t offset));
FUNC_PTR(ssize_t,	pwritev,(int fd, const struct iovec *iov, int iovcnt, off_t offset));

FUNC_PTR(DIR *,		opendir, (const char *name));
FUNC_PTR(struct dirent *, readdir, (DIR *));
FUNC_PTR(int,		readdir_r, (DIR *dirp, struct dirent *entry, struct dirent **result));
FUNC_PTR(int,		readdir64_r, (DIR *dirp, struct dirent64 *entry, struct dirent64 **result));
FUNC_PTR(int,		closedir, (DIR *dirp));

FUNC_PTR(int,		aio_read, (struct aiocb *aiocbp));
FUNC_PTR(int,		aio_read64, (struct aiocb64 *aiocbp));

FUNC_PTR(int,		io_submit, (aio_context_t ctx_id, long nr, struct iocb **iocbpp));

// Needed for our state
FUNC_PTR(int,		setrlimit, (__rlimit_resource_t resource, const struct rlimit *rlim));

// Setup the state based on configuration for all the heavy lifting
int posix_hook_state(void);
int posix_intercept_path(const char* path, char** relpath, char*** mount_pool, size_t* mount_pool_count);

// Intercepted FD tracking
int **fd_bitmap = NULL;
rlim_t fd_bitmap_size = 0;
#define IS_FD_HOOKED(fd) (fd_bitmap_size > (size_t)(fd) && fd_bitmap[(fd)])
#define GET_NEXT_FD(fd, iter) IS_FD_HOOKED(fd) ? fd_bitmap[fd][(size_t)++iter % fd_bitmap[fd][0]] : -1

//-----------------------------------------------------------------------------
// FIXME: Does not work with LD_PRELOAD
// Initializer function called automatically when library is loaded
// __attribute__ ((constructor))
//-----------------------------------------------------------------------------
static void posix_hook_init(void) {
    iotrap_trace = !!getenv("IOTRAP_TRACE");
    const char* iotrap_fiji_str = getenv("IOTRAP_FIJI");
    if (iotrap_fiji_str) {
	iotrap_fiji = strtoul(iotrap_fiji_str, NULL, 10);
    }

    struct rlimit rlim = {0};
    if (getrlimit(RLIMIT_NOFILE, &rlim)) {
	abort();
    }

    fd_bitmap = (int **)calloc(rlim.rlim_cur, sizeof(int *));
    if (NULL == fd_bitmap) {
	abort();
    }
    fd_bitmap_size = rlim.rlim_cur;

    DLSYM_FUNC_PTR(creat);
    DLSYM_FUNC_PTR(open);
    DLSYM_FUNC_PTR(fdopen);
    DLSYM_FUNC_PTR(open64);
    DLSYM_FUNC_PTR(close);
    DLSYM_FUNC_PTR(read);
    DLSYM_FUNC_PTR(write);

    DLSYM_FUNC_PTR(dup);
    DLSYM_FUNC_PTR(dup2);

    DLSYM_FUNC_PTR(fopen);
    DLSYM_FUNC_PTR(fclose);

    DLSYM_FUNC_PTR(fcntl);

    DLSYM_FUNC_PTR(fsync);

    DLSYM_FUNC_PTR(pread);
    DLSYM_FUNC_PTR(pwrite);
    DLSYM_FUNC_PTR(readv);
    DLSYM_FUNC_PTR(writev);
    DLSYM_FUNC_PTR(preadv);
    DLSYM_FUNC_PTR(pwritev);

    DLSYM_FUNC_PTR(opendir);
    DLSYM_FUNC_PTR(readdir);
    DLSYM_FUNC_PTR(readdir_r);
    DLSYM_FUNC_PTR(readdir64_r);
    DLSYM_FUNC_PTR(closedir);

    DLSYM_FUNC_PTR(aio_read);
    DLSYM_FUNC_PTR(aio_read64);

    DLSYM_FUNC_PTR(setrlimit);

    if (posix_hook_state()) {
	abort();
    }

    const char* mount_pools = getenv("IOTRAP_MOUNT_POOLS");
#ifndef NDEBUG
    fprintf(stderr, "IOTRAP framework initialized: mount pools [%s], tracing [%s], fiji [%s:%lu]\n",
	    mount_pools  ?  mount_pools : "NONE",
	    iotrap_trace ?  "enabled"   : "disabled",
	    iotrap_fiji  ?  "enabled"   : "disabled", iotrap_fiji);
#else
    fprintf(stderr, "IOTRAP framework initialized: mount pools [%s], fiji [%s:%lu]\n",
	    mount_pools  ?  mount_pools : "NONE",
    	    iotrap_fiji  ?  "enabled"   : "disabled", iotrap_fiji);
#endif

    return;
}

//-----------------------------------------------------------------------------
//                  Hooked functions custom implementation
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Needed internally to update our fd map size tracking intercepted fd
//-----------------------------------------------------------------------------
int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim) {
    POSIX_HOOK_INIT();

    int ret = setrlimit_orig(resource, rlim);
    if (0 == ret && RLIMIT_NOFILE == resource && fd_bitmap_size < rlim->rlim_cur) {
	const int err = errno;
	int **ptr = (int **)realloc(fd_bitmap, rlim->rlim_cur);
	if (NULL == ptr) {
	    abort();
	}
	fd_bitmap = ptr;
	fd_bitmap_size = rlim->rlim_cur;
	errno = err;
    }

    return ret;
}

// POSIX file IO
//-----------------------------------------------------------------------------
// creat
//-----------------------------------------------------------------------------
int creat(const char *pathname, mode_t mode) {
    POSIX_HOOK_INIT();
    return open64(pathname, O_CREAT|O_WRONLY|O_TRUNC, mode);
}

//-----------------------------------------------------------------------------
// open
//-----------------------------------------------------------------------------
int open(const char *pathname, int flags, ...) {
    POSIX_HOOK_INIT();

    mode_t mode = 0;
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);

    return open64(pathname, flags, mode);
}

//-----------------------------------------------------------------------------
// open64
//-----------------------------------------------------------------------------
int open64(const char *pathname, int flags, ...) {
    POSIX_HOOK_INIT();

    mode_t mode = 0;
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);

    char buff[PATH_MAX] = {0};
    char* relpath = &buff[0];
    char** mount_pool = NULL;

    do {
	size_t mount_pool_count = 0;
	if (!posix_intercept_path(pathname, &relpath, &mount_pool, &mount_pool_count)) {
	    break;
	}
	assert(mount_pool_count > 0 && mount_pool);

	int* pfd = (int *)malloc(sizeof(int) * (mount_pool_count + 1));

	// Too bad we could not intercept it due to memory allocation failure
	if (!pfd) {
	    break;
	}

	// Let us try opening the primary path and proceed only if it succeeds
	pfd[1] = open64_orig(pathname, flags, mode);
	if (pfd[1] < 0) {
	    free(pfd);
	    // Let the retry happen and relay the proper error to the callers
	    break;
	}

	// Update the FD count
	pfd[0] = 1;

	// Add the collection to the tracker
	fd_bitmap[pfd[1]] = pfd;

	// Clear the create/exclusive/truncate bit for successive calls
	flags &= ~O_EXCL;
	flags &= ~O_TRUNC;
	flags &= ~O_CREAT;

	for (size_t cc = 0; cc < mount_pool_count; ++cc) {
	    char altpath[PATH_MAX];
	    snprintf(altpath, sizeof(altpath) - 1, "%s%s", mount_pool[cc], relpath);

	    // Skip the primary path since we have processed it
	    if (0 == strcmp(pathname, altpath)) {
		continue;
	    }

	    const size_t idx = pfd[0] + 1;
	    pfd[idx] = open64_orig(altpath, flags, mode);

	    // Skip failed paths - being more tolerant to configuration errors
	    if (pfd[idx] < 0) {
		continue;
	    }

	    // Add the collection to the tracker
	    fd_bitmap[pfd[idx]] = pfd;

	    // Update the FD count
	    ++pfd[0];
	}

	// Return the FD corresponding to the primary path back to caller
	return pfd[1];
    } while(0);

    return open64_orig(pathname, flags, mode);
}

//-----------------------------------------------------------------------------
// close
//-----------------------------------------------------------------------------
int close(int fd) {
    POSIX_HOOK_INIT();

    // Close the non primary fds
    int* pfd = fd_bitmap[fd];
    if (pfd) {
	for (int cc = 1; cc <= pfd[0]; ++cc) {
	    // Let us close the primary last and relay the errors
	    if (fd != pfd[cc]) {
		(void)close_orig(pfd[cc]);
	    }

	    // Clear the tracking entries
	    assert(pfd == fd_bitmap[pfd[cc]]);
	    fd_bitmap[pfd[cc]] = 0;
	}
	free(pfd);
    }

    return close_orig(fd);
}

//-----------------------------------------------------------------------------
// dup
//-----------------------------------------------------------------------------
int dup(int oldfd) {
    POSIX_HOOK_INIT();

    if (IS_FD_HOOKED(oldfd)) {
	int cc = 0;
	int nfd = -1, err = 0;
	int* pfd = fd_bitmap[oldfd];
	int* pnfd = (int *)malloc(sizeof(int)*(pfd[0] + 1));
	memcpy(pnfd, pfd, sizeof(int)*(pfd[0] + 1));

	for (cc = 1; cc <= pnfd[0]; ++cc) {
	    pnfd[cc] = dup_orig(pnfd[cc]);
	    if (oldfd == pfd[cc]) {
		err = errno;
		nfd = pnfd[cc];
	    }
	}

	// Error handling if something fails
	if (!(nfd < 0)) {
	    fd_bitmap[nfd] = pnfd;
	} else {
	    for (cc = 1; cc < pnfd[0]; ++cc) {
		if (!(pnfd[cc] < 0)) {
		    (void)close_orig(pnfd[cc]);
		}
	    }
	    free(pnfd);
	}

	errno = err;
	return nfd;
    }

    return dup_orig(oldfd);
}

//-----------------------------------------------------------------------------
// dup2
//   WIP: Need to manage the original FDs
//-----------------------------------------------------------------------------
int dup2(int oldfd, int newfd) {
    POSIX_HOOK_INIT();

    if (IS_FD_HOOKED(oldfd)) {
	abort();
#ifdef FIXME
	fprintf(stderr, "Hooking: %s(%d, %d)\n", __FUNCTION__, oldfd, newfd);

	int* pfd = fd_bitmap[oldfd];
	int* pnfd = NULL;
	size_t cc = 0;

	// Close the new fd if open
	if (IS_FD_HOOKED(newfd)) {
	    pnfd = fd_bitmap[newfd];
	    for (cc = 1; cc < pnfd[0]; ++cc) {
		if (!(pnfd[cc] < 0)) {
		    (void)close_orig(pnfd[cc]);
		}
	    }
	}

	// Create new duplicates
	if (!pnfd) {
	    pnfd = (int *)malloc(sizeof(int)*(pfd[0] + 1));
	    memcpy(pnfd, pfd, sizeof(int)*(pfd[0] + 1));
	}

	int nfd = -1;
	for (cc = 1; cc < pnfd[0]; ++cc) {
	    if (oldfd == pfd[cc]) {
		err = errno;
		nfd = pnfd[cc];
	    }
	}

	// Error handling if something fails
	if (!(nfd < 0)) {
	    fd_bitmap[nfd] = pnfd;
	} else {
	    for (cc = 1; cc < pnfd[0]; ++cc) {
		if (!(pnfd[cc] < 0)) {
		    (void)close_orig(pnfd[cc]);
		}
	    }
	    free(pnfd);
	}

	errno = err;
	return nfd;

#endif
    }

    return dup2_orig(oldfd, newfd);
}

//-----------------------------------------------------------------------------
// fcntl
//-----------------------------------------------------------------------------
int fcntl(int fd, int cmd, ...) {
    POSIX_HOOK_INIT();

    struct flock *pfl = NULL;
    va_list ap;
    va_start(ap, cmd);
    pfl = va_arg(ap, struct flock*);
    va_end(ap);

    if (IS_FD_HOOKED(fd)) {
	IOTRAP_TRACE(fprintf(stderr, "Hooking: %s(%d, %d, %p)\n", __FUNCTION__, fd, cmd, pfl));
    }

    return fcntl_orig(fd, cmd, pfl);
}

//-----------------------------------------------------------------------------
// fsync
//-----------------------------------------------------------------------------
int fsync(int fd) {
    return 0;

#if 0
    POSIX_HOOK_INIT();

    // Close the non primary fds
    const int* pfd = fd_bitmap[fd];
    if (pfd) {
	for (int cc = 1; cc <= pfd[0]; ++cc) {
	    // Let us close the primary last and relay the errors
	    if (fd != pfd[cc]) {
		(void)fsync_orig(pfd[cc]);
	    }
	}
    }

    return fsync_orig(fd);
#endif
}

//-----------------------------------------------------------------------------
// fdsync
//-----------------------------------------------------------------------------
int fdsync(int fd) {
    return fsync(fd);
}

//-----------------------------------------------------------------------------
// io_submit
//   Asynchronous IO calls from libaio - Uses syscall and bypasses dlsym
//-----------------------------------------------------------------------------
int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp) {
    POSIX_HOOK_INIT();

    int* pfd = fd_bitmap[iocbpp[0]->aio_fildes];

#ifndef NDEBUG
    // Since we move pfd to actual FD
    const int* pfd_orig = pfd;
#endif

    do {
	if (__builtin_expect(!!pfd, 1)) {
	    int num_fds;

	    if (pfd[0] > 1 && iotrap_fiji) {
		// Skip the primary FD on which a lock has been taken
		num_fds = pfd[0] - 1;
		pfd = &pfd[2];
	    } else {
		num_fds = pfd[0];
		// Skip the index with the FD count
		pfd = &pfd[1];
	    }

	    // Ensure we have a minimum of 1 FD to start
	    assert(num_fds > 0);

	    IOTRAP_TRACE(fprintf(stderr, "Hooking: %s(%lu, %ld, %p)\n", __FUNCTION__, ctx_id, nr, iocbpp));

	    // Handle the case with single IO vec in request
	    if (1 == nr) {
		static size_t randomizer = 0;
		iocbpp[0]->aio_fildes = pfd[++randomizer % num_fds];
		break;
	    }

#ifdef _OPENMP
#pragma omp parallel for
#endif
	    for (long cc = 0; cc < nr; ++cc) {
		// Ensure all FDs in the input IO vecs are same as the first IO vec
		assert(pfd_orig == fd_bitmap[iocbpp[cc]->aio_fildes]);

		iocbpp[cc]->aio_fildes = pfd[cc % num_fds];
	    }
	}
    } while(0);

    return syscall(__NR_io_submit, ctx_id, nr, iocbpp);
}

//-----------------------------------------------------------------------------
//	Extra functions that we might want to intercept in the future
//-----------------------------------------------------------------------------
#ifndef NDEBUG
FILE *fdopen(int fd, const char *mode) {
    POSIX_HOOK_INIT();
    if (IS_FD_HOOKED(fd)) {
	// TODO: We need to remove intercepting the fd
	// Need to figure oue how to do this in multi-threaded environment when other thread
	// might be using the fd set
	abort();
    }

    return fdopen_orig(fd, mode);
}

FILE *fopen(const char *path, const char *mode) {
    POSIX_HOOK_INIT();
    return fopen_orig(path, mode);
}

int fclose(FILE *fp) {
    POSIX_HOOK_INIT();
    return fclose_orig(fp);
}

ssize_t read(int fd, void *buf, size_t count) {
    POSIX_HOOK_INIT();
    return read_orig(fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count) {
    POSIX_HOOK_INIT();
    return write_orig(fd, buf, count);
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
    POSIX_HOOK_INIT();
    return pread_orig(fd, buf, count, offset);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    POSIX_HOOK_INIT();
    return pwrite_orig(fd, buf, count, offset);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
    POSIX_HOOK_INIT();
    return readv_orig(fd, iov, iovcnt);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    POSIX_HOOK_INIT();
    return writev_orig(fd, iov, iovcnt);
}

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    POSIX_HOOK_INIT();
    return preadv_orig(fd, iov, iovcnt, offset);
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    POSIX_HOOK_INIT();
    return pwritev_orig(fd, iov, iovcnt, offset);
}

// Functions operating on directories
DIR* opendir(const char *name) {
    POSIX_HOOK_INIT();
    return opendir_orig(name);
}

struct dirent* readdir(DIR *dirp) {
    POSIX_HOOK_INIT();
    return readdir_orig(dirp);
}

int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result) {
    POSIX_HOOK_INIT();
    return readdir_r_orig(dirp, entry, result);
}

int readdir64_r(DIR *dirp, struct dirent64 *entry, struct dirent64 **result) {
    POSIX_HOOK_INIT();
    return readdir64_r_orig(dirp, entry, result);
}

int closedir(DIR *dirp) {
    POSIX_HOOK_INIT();
    return closedir_orig(dirp);
}

// AIO calls
int aio_read(struct aiocb *aiocbp) {
    POSIX_HOOK_INIT();
    return aio_read_orig(aiocbp);
}

int aio_read64(struct aiocb64 *aiocbp) {
    POSIX_HOOK_INIT();
    return aio_read64_orig(aiocbp);
}

int io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events,
		 struct timespec *timeout) {
    POSIX_HOOK_INIT();
    return syscall(__NR_io_getevents, ctx_id, min_nr, nr, events, timeout);
}

int io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result) {
    POSIX_HOOK_INIT();
    return syscall(__NR_io_cancel, ctx_id, iocb, result);
}

int io_destroy(aio_context_t ctx_id) {
    POSIX_HOOK_INIT();
    return syscall(__NR_io_destroy, ctx_id);
}

int io_setup(unsigned nr_events, aio_context_t *ctxp) {
    POSIX_HOOK_INIT();
    return syscall(__NR_io_setup, nr_events, ctxp);
}
#endif	// not defined NDEBUG

#ifdef __cplusplus
}
#endif