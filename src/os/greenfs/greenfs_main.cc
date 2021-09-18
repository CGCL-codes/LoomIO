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

static void usage()
{
	cout<<"greefs usage:"<<std::endl;
}

int main(int argc, const char **argv){

	vector<const char*> args;
	vector<const char*> def_args;
	def_args.push_back("--leveldb-log=");

	// greenfs_global_pre_init(&def_args, args, CEPH_ENTITY_TYPE_OSD,
	// 			 CODE_ENVIRONMENT_DAEMON,0);

	greenfs_global_init(&def_args, args, CEPH_ENTITY_TYPE_OSD,
				CODE_ENVIRONMENT_DAEMON,
				0, "osd_data");

	//下面这个if是用来判断ceph_heap_profiler_init是否执行的
	if (get_env_bool("CEPH_HEAP_PROFILER_INIT")) {
		cout<<"CEPH_HEAP_PROFILER_INIT==1"<<std::endl;
	}else{
		cout<<"CEPH_HEAP_PROFILER_INIT==0"<<std::endl;
	}
	ceph_heap_profiler_init();//根据输出，由于CEPH_HEAP_PROFILER_INIT为0，所以不执行

	// osd specific args
	//由于无输入，这些参数最后都是false
	bool mkfs = false;
	bool mkjournal = false;
	bool check_wants_journal = false;
	bool check_allows_journal = false;
	bool check_needs_journal = false;
	bool mkkey = false;
	bool flushjournal = false;
	bool dump_journal = false;
	bool convertfilestore = false;
	bool get_osd_fsid = false;
	bool get_cluster_fsid = false;
	bool get_journal_fsid = false;
	bool get_device_fsid = false;
	string device_path;
	std::string dump_pg_log;

	// whoami
	//理论上说因为我们没有create osd，所以这个部分应该是找不到的
	char *end;
	//cout<<"before get_id"<<std::endl;
	const char *id = g_conf->name.get_id().c_str();
	// if(g_conf->name.get_id()!=NULL)
	// id是admin
	cout<<"id:"<<g_conf->name.get_id()<<std::endl;
	int whoami = strtol(id, &end, 10);
	if (*end || end == id || whoami < 0) {
		cout << "must specify '-i #' where # is the osd number" << std::endl;
		usage();
	}

	//创建bluestore
	string store_type = "bluestore";
	g_conf->set_val("osd_objectstore", store_type);
	//在这直接指定data_path
	string data_path = "/users/zhang56/greenfs";
	g_conf->set_val("osd_data", data_path);
	if (g_conf->osd_data.empty()) {
		cout << "must specify '--osd-data=foo' data path" << std::endl;
		usage();
	}else{
		cout<<"data path:"<<g_conf->osd_data<<std::endl;
	}
	ObjectStore *store = ObjectStore::create(g_ceph_context,
						store_type,
						g_conf->osd_data,
						g_conf->osd_journal,
											g_conf->osd_os_flags);
	if (!store) {
		cout << "unable to create object store" << std::endl;
	}else{
		cout << "create object store success!" << std::endl;
	}

	//这几个变量不知道后面有没有用
	string magic;
	uuid_d cluster_fsid, osd_fsid;
	int require_osd_release = 0;
	int w;//w就是who_am_i
	//peek_meta完全可以不要，由我们手动赋值即可
	// int r = OSD::peek_meta(store, &magic, &cluster_fsid, &osd_fsid, &w,
	// 			&require_osd_release);

	

}