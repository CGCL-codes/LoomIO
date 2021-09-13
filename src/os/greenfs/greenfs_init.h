#include <stdint.h>
#include <vector>
#include <boost/intrusive_ptr.hpp>
#include "include/assert.h"
#include "common/code_environment.h"
#include "common/common_init.h"
#include "global/global_init.h"

//class CephContext;//this may need to be further customized

/*
 * global_init is the first initialization function that
 * daemons and utility programs need to call. It takes care of a lot of
 * initialization, including setting up g_ceph_context.
 */

int greenfs_global_init(std::vector < const char * > *alt_def_args,
		 std::vector < const char* >& args,
		 uint32_t module_type,
		 code_environment_t code_env,
		 int flags,
		 const char *data_dir_option = 0,
		 bool run_pre_init = true);


// just the first half; enough to get config parsed but doesn't start up the
// cct or log.
int greenfs_global_pre_init(std::vector < const char * > *alt_def_args,
		     std::vector < const char* >& args,
		     uint32_t module_type, code_environment_t code_env,
		     int flags);


