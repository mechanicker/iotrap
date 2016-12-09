// -*-c++-*-
// Time-stamp: <2016-01-29 10:34:00 dky>
//-----------------------------------------------------------------------------
// File: setup.cc
// Desc: Handles the logic of setting the mount pools for opening and operating
//       on multiple file descriptors
//-----------------------------------------------------------------------------
#include <cassert>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <cstring>
#include <cerrno>

#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/limits.h>

#include <set>
#include <map>
#include <string>
#include <vector>
#include <sstream>

extern "C" bool iotrap_trace;

using namespace std;

class HookEnvironment {
public:
    struct MountPool {
	size_t count;
	char** pool;
    };

    HookEnvironment() {};
    virtual ~HookEnvironment() {};

    bool Setup() {
	bool ret = false;
	do {
	    if (false == (ret = SetupMounts())) {
		break;
	    }
	} while (0);
	return ret;
    }

    // Supports absolute paths only
    bool Intercept(const char* path, char** relpath = NULL,
		   char*** mount_pool = NULL, size_t* mount_pool_count = NULL) {
	// In the absence of realpath, let us ensure we deal with absolute paths only
	if (NULL == path || '/' != path[0]) {
	    return false;
	}

#if 0
	// FIXME: realpath() does not work for non-existent files
	// We could try with the basename...
	char buff[PATH_MAX];
	if (!realpath(path, buff)) {
	    return false;
	}
	string abspath(buff);
#endif

	string abspath(path);
	map<string, string>::iterator mpit;
	for (mpit = _mount_pool.begin(); mpit != _mount_pool.end(); ++mpit) {
	    if (0 == abspath.compare(0, (*mpit).first.length(), (*mpit).first)) {
		if (relpath) {
		    string subpath = abspath.substr((*mpit).first.length());
		    strcpy(*relpath, subpath.c_str());
		}

		if (iotrap_trace) {
		    cerr << "iotrap trace: Using mount pool " << (*mpit).second << endl;
		}

		MountPool &mp = _pool_mounts[(*mpit).second];
		if (mount_pool) {
		    *mount_pool = mp.pool;
		}

		if (mount_pool_count) {
		    *mount_pool_count = mp.count;
		}

		return true;
	    }
	}

	return false;
    }

    void printPools() {
	map<string, MountPool>::iterator it;
	for (it = _pool_mounts.begin(); it != _pool_mounts.end(); ++it) {
	    for (size_t cc = 0; cc < (*it).second.count; ++cc) {
		fprintf(stderr, "DEBUG: pool[%s]:%zu:%s\n", (*it).first.c_str(),
			(*it).second.count, (*it).second.pool[cc]);
	    }
	}

	return;
    }

protected:
    bool SetupBitmap() {
	// Find the max files that can be opened by the process
	struct rlimit rlim = {0};
	if (getrlimit(RLIMIT_NOFILE, &rlim)) {
	    return false;
	}

	return true;
    }

    bool SetupMounts() {
	// IOTRAP_MOUNT_POOL="pool1:/mnt/vol1/1/,/mnt/vol1/2/ pool2:/mnt/vol2/1/,/mnt/vol2/2/"
	const char* iotrap_mount_pool = getenv("IOTRAP_MOUNT_POOLS");
	if (!iotrap_mount_pool) {
	    fprintf(stderr, "IOTRAP framework initialization failed: Mount pools not set\n");
	    return false;
	}

	// Helper index for the next phase of indexing
	map<string, vector<string> > pool_mount;

	string pool_instance;
	istringstream mpss(iotrap_mount_pool);
	while (getline(mpss, pool_instance, ' ')) {
	    string pool, mount;
	    istringstream iss(pool_instance);
	    if (!getline(iss, pool, ':')) {
		continue;
	    }

	    while (getline(iss, mount, ',')) {
		if (mount.empty()) {
		    continue;
		}

		// Add a trailing directory separator if missing
		if ('/' != mount.at(mount.length() - 1)) {
		    mount.push_back('/');
		}

		_mount_pool[mount] = pool;
		pool_mount[pool].push_back(mount);
	    }
	}

	map<string, vector<string> >::iterator pmit;
	for (pmit = pool_mount.begin(); pmit != pool_mount.end(); ++pmit) {
	    MountPool mp = {0, NULL};
	    vector<string> &ms = (*pmit).second;
	    mp.pool = new char*[ms.size()];
	    vector<string>::iterator msit;
	    for (msit = ms.begin(); msit != ms.end(); ++msit) {
		mp.pool[mp.count] = new char[(*msit).size() + 1];
		strcpy(mp.pool[mp.count], (*msit).c_str());
		++mp.count;
	    }
	    _pool_mounts[(*pmit).first] = mp;
	    mp.pool = NULL;
	}

	return true;
    }

private:
    map<string, MountPool> _pool_mounts;
    map<string, string> _mount_pool;
};

// For some reason, cannot be an object - it gets destroyed
static HookEnvironment *hook = NULL;
extern "C" int posix_hook_state(void) {
    hook = new HookEnvironment();
    return (hook->Setup()) ? 0 : -1;
}

extern "C" int posix_intercept_path(const char* path, char** relpath,
				    char*** mount_pool, size_t* mount_pool_count) {
    return hook->Intercept(path, relpath, mount_pool, mount_pool_count) ? 1 : 0;
}

#ifdef UT
int main(int argc, char* argv[]) {
    char buff[PATH_MAX];
    char* relpath = &buff[0];
    char** mount_pool = NULL;
    size_t mount_pool_count = 0;

    (void)posix_hook_state();

    hook->printPools();

    if (posix_intercept_path("/u/dhruva/tmp/datavol.dat", &relpath, &mount_pool, &mount_pool_count)) {
	assert(mount_pool_count > 0 && mount_pool);
	for (size_t ii = 0; ii < mount_pool_count; ++ii) {
	    fprintf(stderr, "Mount pool: %s\n", mount_pool[ii]);
	}
	cerr << relpath << endl;
    }

    if (posix_intercept_path("/u/dhruva/_emacs", &relpath, &mount_pool, &mount_pool_count)) {
	assert(mount_pool_count > 0 && mount_pool);
	for (size_t ii = 0; ii < mount_pool_count; ++ii) {
	    fprintf(stderr, "Mount pool: %s\n", mount_pool[ii]);
	}
	cerr << relpath << endl;
    }

    if (posix_intercept_path("/proc/2557/stat", &relpath, &mount_pool, &mount_pool_count)) {
	assert(mount_pool_count > 0 && mount_pool);
	for (size_t ii = 0; ii < mount_pool_count; ++ii) {
	    fprintf(stderr, "Mount pool: %s\n", mount_pool[ii]);
	}
	cerr << relpath << endl;
    }

    return 0;
}
#endif