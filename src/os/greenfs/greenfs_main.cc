#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <boost/scoped_ptr.hpp>

#include <iostream>
#include <string>
using namespace std;

#include "osd/OSD.h"
#include "os/ObjectStore.h"
#include "mon/MonClient.h"
#include "include/ceph_features.h"

#include "common/config.h"
#include "common/version.h"

#include "mon/MonMap.h"

#include "msg/Messenger.h"

#include "common/Timer.h"
#include "common/TracepointProvider.h"
#include "common/ceph_argparse.h"
#include "common/environment.h"

#include "global/global_init.h"
#include "global/signal_handler.h"
#include "greenfs_init.h"

#include "include/color.h"
#include "common/errno.h"
#include "common/pick_address.h"

#include "perfglue/heap_profiler.h"

#include "include/assert.h"

int main(int argc, const char **argv){

vector<const char*> args;
vector<const char*> def_args;
def_args.push_back("--leveldb-log=");

// greenfs_global_pre_init(&def_args, args, CEPH_ENTITY_TYPE_OSD,
// 			 CODE_ENVIRONMENT_DAEMON,0);

greenfs_global_init(&def_args, args, CEPH_ENTITY_TYPE_OSD,
			 CODE_ENVIRONMENT_DAEMON,
			 0, "osd_data");


if (get_env_bool("CEPH_HEAP_PROFILER_INIT")) {
	cout<<"CEPH_HEAP_PROFILER_INIT==1"<<std::endl;
}else{
	cout<<"CEPH_HEAP_PROFILER_INIT==0"<<std::endl;
}
//ceph_heap_profiler_init();

}