#include "common/ceph_argparse.h"
#include "common/code_environment.h"
#include "common/config.h"
#include "common/debug.h"
#include "common/errno.h"
#include "common/signal.h"
#include "common/version.h"
#include "erasure-code/ErasureCodePlugin.h"
#include "global/global_context.h"
#include "global/pidfile.h"
#include "global/signal_handler.h"
#include "include/compat.h"
#include "include/str_list.h"
#include "common/admin_socket.h"

#include <pwd.h>
#include <grp.h>
#include <errno.h>

#include "greenfs_init.h"

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_

static void global_init_set_globals(CephContext *cct)
{
  g_ceph_context = cct;
  g_conf = cct->_conf;
}

static const char* c_str_or_null(const std::string &str)
{
  if (str.empty()){
      cout<<"empty config file"<<std::endl;
      return NULL;
  }
  return str.c_str();
}

static int chown_path(const std::string &pathname, const uid_t owner, const gid_t group,
		      const std::string &uid_str, const std::string &gid_str)
{
  const char *pathname_cstr = c_str_or_null(pathname);

  if (!pathname_cstr) {
    return 0;
  }

  int r = ::chown(pathname_cstr, owner, group);

  if (r < 0) {
    r = -errno;
    cerr << "warning: unable to chown() " << pathname << " as "
	 << uid_str << ":" << gid_str << ": " << cpp_strerror(r) << std::endl;
  }

  return r;
}

static void output_ceph_version()
{
  char buf[1024];
  snprintf(buf, sizeof(buf), "%s, process %s, pid %d",
	   pretty_version_to_str().c_str(),
	   get_process_name_cpp().c_str(), getpid());
  generic_dout(0) << buf << dendl;
}

int greenfs_global_init(std::vector < const char * > *alt_def_args,
	    std::vector < const char* >& args,
	    uint32_t module_type, code_environment_t code_env,
	    int flags,
	    const char *data_dir_option, bool run_pre_init)
{
  // Ensure we're not calling the global init functions multiple times.
  static bool first_run = true;
  if (run_pre_init) {
    // We will run pre_init from here (default).
    assert(!g_ceph_context && first_run);
    global_pre_init(alt_def_args, args, module_type, code_env, flags);
  } else {
    // Caller should have invoked pre_init manually.
    assert(g_ceph_context && first_run);
  }
  first_run = false;

  // Verify flags have not changed if global_pre_init() has been called
  // manually. If they have, update them.
  if (g_ceph_context->get_init_flags() != flags) {
    g_ceph_context->set_init_flags(flags);
  }

  // signal stuff
  int siglist[] = { SIGPIPE, 0 };
  block_signals(siglist, NULL);

  if (g_conf->fatal_signal_handlers){
      cout<<"install_standard_sighandlers!"<<std::endl;
      install_standard_sighandlers();
  }
    

  if (g_conf->log_flush_on_exit)
    g_ceph_context->_log->set_flush_on_exit();

  // drop privileges?
  ostringstream priv_ss;
 
  // consider --setuser root a no-op, even if we're not root
  if (getuid() != 0) {
    if (g_conf->setuser.length()) {
      cout << "ignoring --setuser " << g_conf->setuser << " since I am not root"
	   << std::endl;
    }
    if (g_conf->setgroup.length()) {
      cout << "ignoring --setgroup " << g_conf->setgroup
	   << " since I am not root" << std::endl;
    }
  } else if (g_conf->setgroup.length() ||
             g_conf->setuser.length()) {
    uid_t uid = 0;  // zero means no change; we can only drop privs here.
    gid_t gid = 0;
    std::string uid_string;
    std::string gid_string;
    std::string home_directory;
    if (g_conf->setuser.length()) {
      char buf[4096];
      struct passwd pa;
      struct passwd *p = 0;

      uid = atoi(g_conf->setuser.c_str());
      if (uid) {
        getpwuid_r(uid, &pa, buf, sizeof(buf), &p);
      } else {
	getpwnam_r(g_conf->setuser.c_str(), &pa, buf, sizeof(buf), &p);
        if (!p) {
	  cout << "unable to look up user '" << g_conf->setuser << "'"
	       << std::endl;
	  exit(1);
	}

        uid = p->pw_uid;
        gid = p->pw_gid;
        uid_string = g_conf->setuser;
      }

      if (p && p->pw_dir != nullptr) {
        home_directory = std::string(p->pw_dir);
      }
    }
    if (g_conf->setgroup.length() > 0) {
      gid = atoi(g_conf->setgroup.c_str());
      if (!gid) {
	char buf[4096];
	struct group gr;
	struct group *g = 0;
	getgrnam_r(g_conf->setgroup.c_str(), &gr, buf, sizeof(buf), &g);
	if (!g) {
	  cout << "unable to look up group '" << g_conf->setgroup << "'"
	       << ": " << cpp_strerror(errno) << std::endl;
	  exit(1);
	}
	gid = g->gr_gid;
	gid_string = g_conf->setgroup;
      }
    }
    if ((uid || gid) &&
	g_conf->setuser_match_path.length()) {
      // induce early expansion of setuser_match_path config option
      string match_path = g_conf->setuser_match_path;
      g_conf->early_expand_meta(match_path, &cout);
      struct stat st;
      int r = ::stat(match_path.c_str(), &st);
      if (r < 0) {
	cout << "unable to stat setuser_match_path "
	     << g_conf->setuser_match_path
	     << ": " << cpp_strerror(errno) << std::endl;
	exit(1);
      }
      if ((uid && uid != st.st_uid) ||
	  (gid && gid != st.st_gid)) {
	cout << "WARNING: will not setuid/gid: " << match_path
	     << " owned by " << st.st_uid << ":" << st.st_gid
	     << " and not requested " << uid << ":" << gid
	     << std::endl;
	uid = 0;
	gid = 0;
	uid_string.erase();
	gid_string.erase();
      } else {
	priv_ss << "setuser_match_path "
		<< match_path << " owned by "
		<< st.st_uid << ":" << st.st_gid << ". ";
      }
    }
    g_ceph_context->set_uid_gid(uid, gid);
    g_ceph_context->set_uid_gid_strings(uid_string, gid_string);
    if ((flags & CINIT_FLAG_DEFER_DROP_PRIVILEGES) == 0) {
      if (setgid(gid) != 0) {
	cout << "unable to setgid " << gid << ": " << cpp_strerror(errno)
	     << std::endl;
	exit(1);
      }
      if (setuid(uid) != 0) {
	cout << "unable to setuid " << uid << ": " << cpp_strerror(errno)
	     << std::endl;
	exit(1);
      }
      if (setenv("HOME", home_directory.c_str(), 1) != 0) {
	cout << "warning: unable to set HOME to " << home_directory << ": "
             << cpp_strerror(errno) << std::endl;
      }
      priv_ss << "set uid:gid to " << uid << ":" << gid << " (" << uid_string << ":" << gid_string << ")";
    } else {
      priv_ss << "deferred set uid:gid to " << uid << ":" << gid << " (" << uid_string << ":" << gid_string << ")";
    }
  }

#if defined(HAVE_SYS_PRCTL_H)
  if (prctl(PR_SET_DUMPABLE, 1) == -1) {
    cout << "warning: unable to set dumpable flag: " << cpp_strerror(errno) << std::endl;
  }
#endif

  // Expand metavariables. Invoke configuration observers. Open log file.
  g_conf->apply_changes(NULL);

  if (g_conf->run_dir.length() &&
      code_env == CODE_ENVIRONMENT_DAEMON &&
      !(flags & CINIT_FLAG_NO_DAEMON_ACTIONS)) {
    int r = ::mkdir(g_conf->run_dir.c_str(), 0755);
    if (r < 0 && errno != EEXIST) {
      cout << "warning: unable to create " << g_conf->run_dir << ": " << cpp_strerror(errno) << std::endl;
    }
  }

  register_assert_context(g_ceph_context);

  // call all observers now.  this has the side-effect of configuring
  // and opening the log file immediately.
  g_conf->call_all_observers();

  if (priv_ss.str().length()) {
    dout(0) << priv_ss.str() << dendl;
  }

  if ((flags & CINIT_FLAG_DEFER_DROP_PRIVILEGES) &&
      (g_ceph_context->get_set_uid() || g_ceph_context->get_set_gid())) {
    // Fix ownership on log files and run directories if needed.
    // Admin socket files are chown()'d during the common init path _after_
    // the service thread has been started. This is sadly a bit of a hack :(
    chown_path(g_conf->run_dir,
	       g_ceph_context->get_set_uid(),
	       g_ceph_context->get_set_gid(),
	       g_ceph_context->get_set_uid_string(),
	       g_ceph_context->get_set_gid_string());
    g_ceph_context->_log->chown_log_file(
      g_ceph_context->get_set_uid(),
      g_ceph_context->get_set_gid());
  }

  // Now we're ready to complain about config file parse errors
  g_conf->complain_about_parse_errors(g_ceph_context);

  // test leak checking
  if (g_conf->debug_deliberately_leak_memory) {
    derr << "deliberately leaking some memory" << dendl;
    char *s = new char[1234567];
    (void)s;
    // cppcheck-suppress memleak
  }

  if (code_env == CODE_ENVIRONMENT_DAEMON && !(flags & CINIT_FLAG_NO_DAEMON_ACTIONS))
    output_ceph_version();

  if (g_ceph_context->crush_location.init_on_startup()) {
    cout << " failed to init_on_startup : " << cpp_strerror(errno) << std::endl;
    exit(1);
  }

  return 0;
}

int greenfs_global_pre_init(std::vector < const char * > *alt_def_args,
		     std::vector < const char* >& args,
		     uint32_t module_type, code_environment_t code_env,
		     int flags)
{
  std::string conf_file_list;
  std::string cluster = "";
  //iparams:  entity_type,name
  //ceph_argparse_early_args只根据module_type填充了iparams,cluster和conf_file_list都不变
  CephInitParameters iparams = ceph_argparse_early_args(args, module_type,
							&cluster, &conf_file_list);
  CephContext *cct = common_preinit(iparams, code_env, flags);
  cct->_conf->cluster = cluster;
  //输出cluster为空
  //cout<<"cluster:"<<cluster<<std::endl;
  //初始化全局的那两个变量
  global_init_set_globals(cct);
  md_config_t *conf = cct->_conf;

  if (alt_def_args)//这个没用
    conf->parse_argv(*alt_def_args);  // alternative default args

  //conf_file_list是空的，会将clustername变成ceph
  int ret = conf->parse_config_files(c_str_or_null(conf_file_list),
				     &cout, flags);
  if (ret == -EDOM) {
    cout<<"global_init: error parsing config file.\n"<<std::endl;
    _exit(1);
  }
  else if (ret == -ENOENT) {
    if (!(flags & CINIT_FLAG_NO_DEFAULT_CONFIG_FILE)) {
      if (conf_file_list.length()) {
	ostringstream oss;
	oss << "global_init: unable to open config file from search list "
	    << conf_file_list << "\n";
        cout<<oss.str()<<std::endl;
        _exit(1);
      } else {
        cout<< "did not load config file, using default settings." << std::endl;
      }
    }
  }
  else if (ret) {
    cout<<"global_init: error reading config file.\n"<<std::endl;
    _exit(1);
  }

  //设置keyring为ceph_keyring
  conf->parse_env(); // environment variables override
  //根据args覆盖conf中的一些参数
  conf->parse_argv(args); // argv override

  // Now we're ready to complain about config file parse errors
  //这个主要输出md_config_t中的parse_errors中的string
  g_conf->complain_about_parse_errors(g_ceph_context);

  return 0;
}