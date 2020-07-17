// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "acconfig.h"
#include "options.h"
#include "common/Formatter.h"

// Helpers for validators
#include "include/stringify.h"
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>

// Definitions for enums
#include "common/perf_counters.h"


void Option::dump_value(const char *field_name,
    const Option::value_t &v, Formatter *f) const
{
  if (boost::get<boost::blank>(&v)) {
    // This should be nil but Formatter doesn't allow it.
    f->dump_string(field_name, "");
  } else if (type == TYPE_UINT) {
    f->dump_unsigned(field_name, boost::get<uint64_t>(v));
  } else if (type == TYPE_INT) {
    f->dump_int(field_name, boost::get<int64_t>(v));
  } else if (type == TYPE_STR) {
    f->dump_string(field_name, boost::get<std::string>(v));
  } else if (type == TYPE_FLOAT) {
    f->dump_float(field_name, boost::get<double>(v));
  } else if (type == TYPE_BOOL) {
    f->dump_bool(field_name, boost::get<bool>(v));
  } else {
    f->dump_stream(field_name) << v;
  }
}

int Option::pre_validate(std::string *new_value, std::string *err) const
{
  if (validator) {
    return validator(new_value, err);
  } else {
    return 0;
  }
}

int Option::validate(const Option::value_t &new_value, std::string *err) const
{
  // Generic validation: min
  if (!boost::get<boost::blank>(&(min))) {
    if (new_value < min) {
      std::ostringstream oss;
      oss << "Value '" << new_value << "' is below minimum " << min;
      *err = oss.str();
      return -EINVAL;
    }
  }

  // Generic validation: max
  if (!boost::get<boost::blank>(&(max))) {
    if (new_value > max) {
      std::ostringstream oss;
      oss << "Value '" << new_value << "' exceeds maximum " << max;
      *err = oss.str();
      return -EINVAL;
    }
  }

  // Generic validation: enum
  if (!enum_allowed.empty() && type == Option::TYPE_STR) {
    auto found = std::find(enum_allowed.begin(), enum_allowed.end(),
                           boost::get<std::string>(new_value));
    if (found == enum_allowed.end()) {
      std::ostringstream oss;
      oss << "'" << new_value << "' is not one of the permitted "
                 "values: " << joinify(enum_allowed.begin(),
                                       enum_allowed.end(),
                                       std::string(", "));
      *err = oss.str();
      return -EINVAL;
    }
  }

  return 0;
}

void Option::dump(Formatter *f) const
{
  f->open_object_section("option");
  f->dump_string("name", name);

  f->dump_string("type", type_to_str(type));

  f->dump_string("level", level_to_str(level));

  f->dump_string("desc", desc);
  f->dump_string("long_desc", long_desc);

  dump_value("default", value, f);
  dump_value("daemon_default", daemon_value, f);

  f->open_array_section("tags");
  for (const auto t : tags) {
    f->dump_string("tag", t);
  }
  f->close_section();

  f->open_array_section("services");
  for (const auto s : services) {
    f->dump_string("service", s);
  }
  f->close_section();

  f->open_array_section("see_also");
  for (const auto sa : see_also) {
    f->dump_string("see_also", sa);
  }
  f->close_section();

  if (type == TYPE_STR) {
    f->open_array_section("enum_values");
    for (const auto &ea : enum_allowed) {
      f->dump_string("enum_value", ea);
    }
    f->close_section();
  }

  dump_value("min", min, f);
  dump_value("max", max, f);

  f->close_section();
}

constexpr unsigned long long operator"" _min (unsigned long long min) {
  return min * 60;
}
constexpr unsigned long long operator"" _hr (unsigned long long hr) {
  return hr * 60 * 60;
}
constexpr unsigned long long operator"" _day (unsigned long long day) {
  return day * 60 * 60 * 24;
}
constexpr unsigned long long operator"" _K (unsigned long long n) {
  return n << 10;
}
constexpr unsigned long long operator"" _M (unsigned long long n) {
  return n << 20;
}
constexpr unsigned long long operator"" _G (unsigned long long n) {
  return n << 30;
}

std::vector<Option> get_global_options() {
  return std::vector<Option>({
    Option("host", Option::TYPE_STR, Option::LEVEL_BASIC)
    .set_description("local hostname")
    .set_long_description("if blank, ceph assumes the short hostname (hostname -s)")
    .add_service("common")
    .add_tag("network"),

    Option("fsid", Option::TYPE_UUID, Option::LEVEL_BASIC)
    .set_description("cluster fsid (uuid)")
    .add_service("common")
    .add_tag("service"),

    Option("public_addr", Option::TYPE_ADDR, Option::LEVEL_BASIC)
    .set_description("public-facing address to bind to")
    .add_service({"mon", "mds", "osd", "mgr"}),

    Option("public_bind_addr", Option::TYPE_ADDR, Option::LEVEL_ADVANCED)
    .set_default(entity_addr_t())
    .add_service("mon")
    .set_description(""),

    Option("cluster_addr", Option::TYPE_ADDR, Option::LEVEL_BASIC)
    .set_description("cluster-facing address to bind to")
    .add_service("osd")
    .add_tag("network"),

    Option("public_network", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .add_service({"mon", "mds", "osd", "mgr"})
    .add_tag("network")
    .set_description("Network(s) from which to choose a public address to bind to"),

    Option("public_network_interface", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .add_service({"mon", "mds", "osd", "mgr"})
    .add_tag("network")
    .set_description("Interface name(s) from which to choose an address from a public_network to bind to; public_network must also be specified.")
    .add_see_also("public_network"),

    Option("cluster_network", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .add_service("osd")
    .add_tag("network")
    .set_description("Network(s) from which to choose a cluster address to bind to"),

    Option("cluster_network_interface", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .add_service({"mon", "mds", "osd", "mgr"})
    .add_tag("network")
    .set_description("Interface name(s) from which to choose an address from a cluster_network to bind to; cluster_network must also be specified.")
    .add_see_also("cluster_network"),

    Option("monmap", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("path to MonMap file")
    .set_long_description("This option is normally used during mkfs, but can also "
  			"be used to identify which monitors to connect to.")
    .add_service("mon")
    .add_tag("mkfs"),

    Option("mon_host", Option::TYPE_STR, Option::LEVEL_BASIC)
    .set_description("list of hosts or addresses to search for a monitor")
    .set_long_description("This is a comma, whitespace, or semicolon separated "
  			"list of IP addresses or hostnames. Hostnames are "
  			"resolved via DNS and all A or AAAA records are "
  			"included in the search list.")
    .add_service("common"),

    Option("mon_dns_srv_name", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("ceph-mon")
    .set_description("name of DNS SRV record to check for monitor addresses")
    .add_service("common")
    .add_tag("network")
    .add_see_also("mon_host"),

    // lockdep
    Option("lockdep", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_description("enable lockdep lock dependency analyzer")
    .add_service("common"),

    Option("lockdep_force_backtrace", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_description("always gather current backtrace at every lock")
    .add_service("common")
    .add_see_also("lockdep"),

    Option("run_dir", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("/var/run/ceph")
    .set_description("path for the 'run' directory for storing pid and socket files")
    .add_service("common")
    .add_see_also("admin_socket"),

    Option("admin_socket", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_daemon_default("$run_dir/$cluster-$name.asok")
    .set_description("path for the runtime control socket file, used by the 'ceph daemon' command")
    .add_service("common"),

    Option("admin_socket_mode", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("file mode to set for the admin socket file, e.g, '0755'")
    .add_service("common")
    .add_see_also("admin_socket"),

    Option("crushtool", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("name of the 'crushtool' utility")
    .add_service("mon"),

    // daemon
    Option("daemonize", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_daemon_default(true)
    .set_description("whether to daemonize (background) after startup")
    .add_service({"mon", "mgr", "osd", "mds"})
    .add_tag("service")
    .add_see_also({"pid_file", "chdir"}),

    Option("setuser", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("uid or user name to switch to on startup")
    .set_long_description("This is normally specified by the systemd unit file.")
    .add_service({"mon", "mgr", "osd", "mds"})
    .add_tag("service")
    .add_see_also("setgroup"),

    Option("setgroup", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("gid or group name to switch to on startup")
    .set_long_description("This is normally specified by the systemd unit file.")
    .add_service({"mon", "mgr", "osd", "mds"})
    .add_tag("service")
    .add_see_also("setuser"),

    Option("setuser_match_path", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("if set, setuser/setgroup is condition on this path matching ownership")
    .set_long_description("If setuser or setgroup are specified, and this option is non-empty, then the uid/gid of the daemon will only be changed if the file or directory specified by this option has a matching uid and/or gid.  This exists primarily to allow switching to user ceph for OSDs to be conditional on whether the osd data contents have also been chowned after an upgrade.  This is normally specified by the systemd unit file.")
    .add_service({"mon", "mgr", "osd", "mds"})
    .add_tag("service")
    .add_see_also({"setuser", "setgroup"}),

    Option("pid_file", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("path to write a pid file (if any)")
    .add_service({"mon", "mgr", "osd", "mds"})
    .add_tag("service"),

    Option("chdir", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("path to chdir(2) to after daemonizing")
    .add_service({"mon", "mgr", "osd", "mds"})
    .add_tag("service")
    .add_see_also("daemonize"),

    Option("fatal_signal_handlers", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description("whether to register signal handlers for SIGABRT etc that dump a stack trace")
    .set_long_description("This is normally true for daemons and values for libraries.")
    .add_service({"mon", "mgr", "osd", "mds"})
    .add_tag("service"),

    // restapi
    Option("restapi_log_level", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("default set by python code"),

    Option("restapi_base_url", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("default set by python code"),

    Option("erasure_code_dir", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default(CEPH_PKGLIBDIR"/erasure-code")
    .set_description("directory where erasure-code plugins can be found")
    .add_service({"mon", "osd"})
    .set_safe(),

    // logging
    Option("log_file", Option::TYPE_STR, Option::LEVEL_BASIC)
    .set_default("")
    .set_daemon_default("/var/log/ceph/$cluster-$name.log")
    .set_description("path to log file")
    .add_see_also({"log_to_stderr",
                   "err_to_stderr",
                   "log_to_syslog",
                   "err_to_syslog"}),

    Option("log_max_new", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1000)
    .set_description("max unwritten log entries to allow before waiting to flush to the log")
    .add_see_also("log_max_recent"),

    Option("log_max_recent", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(500)
    .set_daemon_default(10000)
    .set_description("recent log entries to keep in memory to dump in the event of a crash")
    .set_long_description("The purpose of this option is to log at a higher debug level only to the in-memory buffer, and write out the detailed log messages only if there is a crash.  Only log entries below the lower log level will be written unconditionally to the log.  For example, debug_osd=1/5 will write everything <= 1 to the log unconditionally but keep entries at levels 2-5 in memory.  If there is a seg fault or assertion failure, all entries will be dumped to the log."),

    Option("log_to_stderr", Option::TYPE_BOOL, Option::LEVEL_BASIC)
    .set_default(true)
    .set_daemon_default(false)
    .set_description("send log lines to stderr"),

    Option("err_to_stderr", Option::TYPE_BOOL, Option::LEVEL_BASIC)
    .set_default(false)
    .set_daemon_default(true)
    .set_description("send critical error log lines to stderr"),

    Option("log_stderr_prefix", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_description("String to prefix log messages with when sent to stderr"),

    Option("log_to_syslog", Option::TYPE_BOOL, Option::LEVEL_BASIC)
    .set_default(false)
    .set_description("send log lines to syslog facility"),

    Option("err_to_syslog", Option::TYPE_BOOL, Option::LEVEL_BASIC)
    .set_default(false)
    .set_description("send critical error log lines to syslog facility"),

    Option("log_flush_on_exit", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description("set a process exit handler to ensure the log is flushed on exit"),

    Option("log_stop_at_utilization", Option::TYPE_FLOAT, Option::LEVEL_BASIC)
    .set_default(.97)
    .set_min_max(0.0, 1.0)
    .set_description("stop writing to the log file when device utilization reaches this ratio")
    .add_see_also("log_file"),

    Option("log_to_graylog", Option::TYPE_BOOL, Option::LEVEL_BASIC)
    .set_default(false)
    .set_description("send log lines to remote graylog server")
    .add_see_also({"err_to_graylog",
                   "log_graylog_host",
                   "log_graylog_port"}),

    Option("err_to_graylog", Option::TYPE_BOOL, Option::LEVEL_BASIC)
    .set_default(false)
    .set_description("send critical error log lines to remote graylog server")
    .add_see_also({"log_to_graylog",
                   "log_graylog_host",
                   "log_graylog_port"}),

    Option("log_graylog_host", Option::TYPE_STR, Option::LEVEL_BASIC)
    .set_default("127.0.0.1")
    .set_description("address or hostname of graylog server to log to")
    .add_see_also({"log_to_graylog",
                   "err_to_graylog",
                   "log_graylog_port"}),

    Option("log_graylog_port", Option::TYPE_INT, Option::LEVEL_BASIC)
    .set_default(12201)
    .set_description("port number for the remote graylog server")
    .add_see_also("log_graylog_host"),



    // unmodified
    Option("clog_to_monitors", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("default=true")
    .set_description(""),

    Option("clog_to_syslog", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("false")
    .set_description(""),

    Option("clog_to_syslog_level", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("info")
    .set_description(""),

    Option("clog_to_syslog_facility", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("default=daemon audit=local0")
    .set_description(""),

    Option("clog_to_graylog", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("false")
    .set_description(""),

    Option("clog_to_graylog_host", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("127.0.0.1")
    .set_description(""),

    Option("clog_to_graylog_port", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("12201")
    .set_description(""),

    Option("mon_cluster_log_to_stderr", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description("Send cluster log messages to stderr (prefixed by channel)"),

    Option("mon_cluster_log_to_syslog", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("default=false")
    .set_description(""),

    Option("mon_cluster_log_to_syslog_level", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("info")
    .set_description(""),

    Option("mon_cluster_log_to_syslog_facility", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("daemon")
    .set_description(""),

    Option("mon_cluster_log_file", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("default=/var/log/ceph/$cluster.$channel.log cluster=/var/log/ceph/$cluster.log")
    .set_description(""),

    Option("mon_cluster_log_file_level", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("debug")
    .set_description(""),

    Option("mon_cluster_log_to_graylog", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("false")
    .set_description(""),

    Option("mon_cluster_log_to_graylog_host", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("127.0.0.1")
    .set_description(""),

    Option("mon_cluster_log_to_graylog_port", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("12201")
    .set_description(""),

    Option("enable_experimental_unrecoverable_data_corrupting_features", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("plugin_dir", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default(CEPH_PKGLIBDIR)
    .set_description("")
    .set_safe(),

    Option("xio_trace_mempool", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("xio_trace_msgcnt", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("xio_trace_xcon", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("xio_queue_depth", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(128)
    .set_description(""),

    Option("xio_mp_min", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(128)
    .set_description(""),

    Option("xio_mp_max_64", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(65536)
    .set_description(""),

    Option("xio_mp_max_256", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(8192)
    .set_description(""),

    Option("xio_mp_max_1k", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(8192)
    .set_description(""),

    Option("xio_mp_max_page", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(4096)
    .set_description(""),

    Option("xio_mp_max_hint", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(4096)
    .set_description(""),

    Option("xio_portal_threads", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(2)
    .set_description(""),

    Option("xio_max_conns_per_portal", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(32)
    .set_description(""),

    Option("xio_transport_type", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("rdma")
    .set_description(""),

    Option("xio_max_send_inline", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(512)
    .set_description(""),

    Option("compressor_zlib_isal", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("compressor_zlib_level", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(5)
    .set_description(""),

    Option("async_compressor_enabled", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("async_compressor_type", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("snappy")
    .set_description(""),

    Option("async_compressor_threads", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(2)
    .set_description(""),

    Option("async_compressor_thread_timeout", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(5)
    .set_description(""),

    Option("async_compressor_thread_suicide_timeout", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(30)
    .set_description(""),

    Option("plugin_crypto_accelerator", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("crypto_isal")
    .set_description(""),

    Option("mempool_debug", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("key", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description("Authentication key")
    .set_long_description("A CephX authentication key, base64 encoded.  It normally looks something like 'AQAtut9ZdMbNJBAAHz6yBAWyJyz2yYRyeMWDag=='.")
    .add_see_also("keyfile")
    .add_see_also("keyring"),

    Option("keyfile", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description("Path to a file containing a key")
    .set_long_description("The file should contain a CephX authentication key and optionally a trailing newline, but nothing else.")
    .add_see_also("key"),

    Option("keyring", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default(
      "/etc/ceph/$cluster.$name.keyring,/etc/ceph/$cluster.keyring,"
      "/etc/ceph/keyring,/etc/ceph/keyring.bin," 
  #if defined(__FreeBSD)
      "/usr/local/etc/ceph/$cluster.$name.keyring,"
      "/usr/local/etc/ceph/$cluster.keyring,"
      "/usr/local/etc/ceph/keyring,/usr/local/etc/ceph/keyring.bin," 
  #endif
    )
    .set_description("Path to a keyring file.")
    .set_long_description("A keyring file is an INI-style formatted file where the section names are client or daemon names (e.g., 'osd.0') and each section contains a 'key' property with CephX authentication key as the value.")
    .add_see_also("key")
    .add_see_also("keyfile"),

    Option("heartbeat_interval", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(5)
    .set_description(""),

    Option("heartbeat_file", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("heartbeat_inject_failure", Option::TYPE_INT, Option::LEVEL_DEV)
    .set_default(0)
    .set_description(""),

    Option("perf", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("ms_type", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("async+posix")
    .set_description("")
    .set_safe(),

    Option("ms_public_type", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("ms_cluster_type", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("ms_tcp_nodelay", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("ms_tcp_rcvbuf", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description(""),

    Option("ms_tcp_prefetch_max_size", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(4_K)
    .set_description(""),

    Option("ms_initial_backoff", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.2)
    .set_description(""),

    Option("ms_max_backoff", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(15.0)
    .set_description(""),

    Option("ms_crc_data", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("ms_crc_header", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("ms_die_on_bad_msg", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("ms_die_on_unhandled_msg", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("ms_die_on_old_message", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("ms_die_on_skipped_message", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("ms_dispatch_throttle_bytes", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(100 << 20)
    .set_description(""),

    Option("ms_bind_ipv6", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("ms_bind_port_min", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(6800)
    .set_description(""),

    Option("ms_bind_port_max", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(7300)
    .set_description(""),

    Option("ms_bind_retry_count", Option::TYPE_INT, Option::LEVEL_ADVANCED)
  #if !defined(__FreeBSD__)
    .set_default(3)
  #else
    // FreeBSD does not use SO_REAUSEADDR so allow for a bit more time per default
    .set_default(6)
  #endif
    .set_description(""),

    Option("ms_bind_retry_delay", Option::TYPE_INT, Option::LEVEL_ADVANCED)
  #if !defined(__FreeBSD__)
    .set_default(5)
  #else
    // FreeBSD does not use SO_REAUSEADDR so allow for a bit more time per default
    .set_default(6)
  #endif
    .set_description(""),

    Option("ms_bind_before_connect", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("ms_tcp_listen_backlog", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(512)
    .set_description(""),

    Option("ms_rwthread_stack_bytes", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(1_M)
    .set_description(""),

    Option("ms_connection_ready_timeout", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(10)
    .set_description("Time before we declare a not yet ready connection as dead (seconds)"),

    Option("ms_connection_idle_timeout", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(900)
    .set_description(""),

    Option("ms_pq_max_tokens_per_priority", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(16777216)
    .set_description(""),

    Option("ms_pq_min_cost", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(65536)
    .set_description(""),

    Option("ms_inject_socket_failures", Option::TYPE_UINT, Option::LEVEL_DEV)
    .set_default(0)
    .set_description(""),

    Option("ms_inject_delay_type", Option::TYPE_STR, Option::LEVEL_DEV)
    .set_default("")
    .set_description("")
    .set_safe(),

    Option("ms_inject_delay_msg_type", Option::TYPE_STR, Option::LEVEL_DEV)
    .set_default("")
    .set_description(""),

    Option("ms_inject_delay_max", Option::TYPE_FLOAT, Option::LEVEL_DEV)
    .set_default(1)
    .set_description(""),

    Option("ms_inject_delay_probability", Option::TYPE_FLOAT, Option::LEVEL_DEV)
    .set_default(0)
    .set_description(""),

    Option("ms_inject_internal_delays", Option::TYPE_FLOAT, Option::LEVEL_DEV)
    .set_default(0)
    .set_description(""),

    Option("ms_dump_on_send", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("ms_dump_corrupt_message_level", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1)
    .set_description(""),

    Option("ms_async_op_threads", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(3)
    .set_description(""),

    Option("ms_async_max_op_threads", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(5)
    .set_description(""),

    Option("ms_async_set_affinity", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("ms_async_affinity_cores", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("ms_async_rdma_device_name", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("ms_async_rdma_enable_hugepage", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("ms_async_rdma_buffer_size", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(128_K)
    .set_description(""),

    Option("ms_async_rdma_send_buffers", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(1_K)
    .set_description(""),

    Option("ms_async_rdma_receive_buffers", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(1024)
    .set_description(""),

    Option("ms_async_rdma_port_num", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(1)
    .set_description(""),

    Option("ms_async_rdma_polling_us", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(1000)
    .set_description(""),

    Option("ms_async_rdma_local_gid", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("ms_async_rdma_roce_ver", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1)
    .set_description(""),

    Option("ms_async_rdma_sl", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(3)
    .set_description(""),

    Option("ms_async_rdma_dscp", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(96)
    .set_description(""),

    Option("ms_max_accept_failures", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(4)
    .set_description("The maximum number of consecutive failed accept() calls before "
                     "considering the daemon is misconfigured and abort it."),

    Option("ms_dpdk_port_id", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description(""),

    Option("ms_dpdk_coremask", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("1")
    .set_description("")
    .set_safe(),

    Option("ms_dpdk_memory_channel", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("4")
    .set_description(""),

    Option("ms_dpdk_hugepages", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("ms_dpdk_pmd", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("ms_dpdk_host_ipv4_addr", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description("")
    .set_safe(),

    Option("ms_dpdk_gateway_ipv4_addr", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description("")
    .set_safe(),

    Option("ms_dpdk_netmask_ipv4_addr", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description("")
    .set_safe(),

    Option("ms_dpdk_lro", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("ms_dpdk_hw_flow_control", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("ms_dpdk_hw_queue_weight", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(1)
    .set_description(""),

    Option("ms_dpdk_debug_allow_loopback", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("ms_dpdk_rx_buffer_count_per_core", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(8192)
    .set_description(""),

    Option("inject_early_sigterm", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("mon_data", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("/var/lib/ceph/mon/$cluster-$id")
    .set_description(""),

    Option("mon_initial_members", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("mon_compact_on_start", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_compact_on_bootstrap", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_compact_on_trim", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_osd_cache_size", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(500)
    .set_description(""),

    Option("mon_cpu_threads", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(4)
    .set_description(""),

    Option("mon_osd_mapping_pgs_per_chunk", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(4096)
    .set_description(""),

    Option("mon_clean_pg_upmaps_per_chunk", Option::TYPE_INT, Option::LEVEL_DEV)
    .set_default(256)
    .add_service("mon")
    .set_description("granularity of PG upmap validation background work"),

    Option("mon_osd_max_creating_pgs", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1024)
    .set_description(""),

    Option("mon_tick_interval", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(5)
    .set_description(""),

    Option("mon_session_timeout", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(300)
    .set_description(""),

    Option("mon_subscribe_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(1_day)
    .set_description(""),

    Option("mon_delta_reset_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(10)
    .set_description(""),

    Option("mon_osd_laggy_halflife", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1_hr)
    .set_description(""),

    Option("mon_osd_laggy_weight", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.3)
    .set_description(""),

    Option("mon_osd_laggy_max_interval", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(300)
    .set_description(""),

    Option("mon_osd_adjust_heartbeat_grace", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_osd_adjust_down_out_interval", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_osd_auto_mark_in", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_osd_auto_mark_auto_out_in", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_osd_auto_mark_new_in", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_osd_destroyed_out_interval", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(600)
    .set_description(""),

    Option("mon_osd_down_out_interval", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(600)
    .set_description(""),

    Option("mon_osd_down_out_subtree_limit", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("rack")
    .set_description(""),

    Option("mon_osd_min_up_ratio", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.3)
    .set_description(""),

    Option("mon_osd_min_in_ratio", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.75)
    .set_description(""),

    Option("mon_osd_warn_op_age", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(32)
    .set_description(""),

    Option("mon_osd_err_op_age_ratio", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(128)
    .set_description(""),

    Option("mon_osd_max_split_count", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(32)
    .set_description(""),

    Option("mon_osd_allow_primary_temp", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_osd_allow_primary_affinity", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_osd_prime_pg_temp", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_osd_prime_pg_temp_max_time", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.5)
    .set_description(""),

    Option("mon_osd_prime_pg_temp_max_estimate", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.25)
    .set_description(""),

    Option("mon_osd_pool_ec_fast_read", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_stat_smooth_intervals", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(6)
    .set_min(1)
    .add_service("mgr")
    .set_description("number of PGMaps stats over which we calc the average read/write throughput of the whole cluster"),

    Option("mon_election_timeout", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(5)
    .set_description(""),

    Option("mon_lease", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(5)
    .set_description(""),

    Option("mon_lease_renew_interval_factor", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.6)
    .set_description(""),

    Option("mon_lease_ack_timeout_factor", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(2.0)
    .set_description(""),

    Option("mon_accept_timeout_factor", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(2.0)
    .set_description(""),

    Option("mon_clock_drift_allowed", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.050)
    .set_description(""),

    Option("mon_clock_drift_warn_backoff", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(5)
    .set_description(""),

    Option("mon_timecheck_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(300.0)
    .set_description(""),

    Option("mon_timecheck_skew_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(30.0)
    .set_description(""),

    Option("mon_pg_stuck_threshold", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(60)
    .set_description("number of seconds after which pgs can be considered stuck inactive, unclean, etc")
    .set_long_description("see doc/control.rst under dump_stuck for more info")
    .add_service("mgr"),

    Option("mon_pg_min_inactive", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(1)
    .set_description(""),

    Option("mon_pg_warn_min_per_osd", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(30)
    .set_description("minimal number PGs per (in) osd before we warn the admin"),

    Option("mon_max_pg_per_osd", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(250)
    .set_description("Max number of PGs per OSD the cluster will allow"),

    Option("mon_pg_warn_max_object_skew", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(10.0)
    .set_description("max skew few average in objects per pg")
    .add_service("mgr"),

    Option("mon_pg_warn_min_objects", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(10000)
    .set_description("do not warn below this object #")
    .add_service("mgr"),

    Option("mon_pg_warn_min_pool_objects", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1000)
    .set_description("do not warn on pools below this object #")
    .add_service("mgr"),

    Option("mon_pg_check_down_all_threshold", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.5)
    .set_description("threshold of down osds after which we check all pgs")
    .add_service("mgr"),

    Option("mon_cache_target_full_warn_ratio", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.66)
    .set_description(""),

    Option("mon_osd_full_ratio", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.95)
    .set_description(""),

    Option("mon_osd_backfillfull_ratio", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.90)
    .set_description(""),

    Option("mon_osd_nearfull_ratio", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.85)
    .set_description(""),

    Option("mon_osd_initial_require_min_compat_client", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("jewel")
    .set_description(""),

    Option("mon_allow_pool_delete", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_fake_pool_delete", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_globalid_prealloc", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(10000)
    .set_description(""),

    Option("mon_osd_report_timeout", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(900)
    .set_description(""),

    Option("mon_force_standby_active", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_warn_on_legacy_crush_tunables", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_crush_min_required_version", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("firefly")
    .set_description(""),

    Option("mon_warn_on_crush_straw_calc_version_zero", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_warn_on_osd_down_out_interval_zero", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_warn_on_cache_pools_without_hit_sets", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_warn_on_pool_no_app", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(true)
    .set_description("Enable POOL_APP_NOT_ENABLED health check"),

    Option("mon_warn_on_too_few_osds", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .add_service("mgr")
    .set_description("Issue a health warning if there are fewer OSDs than osd_pool_default_size"),

    Option("mon_warn_on_slow_ping_time", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .add_service("mgr")
    .set_description("Override mon_warn_on_slow_ping_ratio with specified threshold in milliseconds")
    .add_see_also("mon_warn_on_slow_ping_ratio"),

    Option("mon_warn_on_slow_ping_ratio", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.05)
    .add_service("mgr")
    .set_description("Issue a health warning if heartbeat ping longer than percentage of osd_heartbeat_grace")
    .add_see_also("osd_heartbeat_grace")
    .add_see_also("mon_warn_on_slow_ping_time"),

    Option("mon_min_osdmap_epochs", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(500)
    .set_description(""),

    Option("mon_max_pgmap_epochs", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(500)
    .set_description(""),

    Option("mon_max_log_epochs", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(500)
    .set_description(""),

    Option("mon_max_mdsmap_epochs", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(500)
    .set_description(""),

    Option("mon_max_mgrmap_epochs", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(500)
    .set_description(""),

    Option("mon_max_osd", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(10000)
    .set_description(""),

    Option("mon_probe_timeout", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(2.0)
    .set_description(""),

    Option("mon_client_bytes", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(100ul << 20)
    .set_description(""),

    Option("mon_mgr_proxy_client_bytes_ratio", Option::TYPE_FLOAT, Option::LEVEL_DEV)
    .set_default(.3)
    .set_description("ratio of mon_client_bytes that can be consumed by "
                     "proxied mgr commands before we error out to client"),

    Option("mon_log_max_summary", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(50)
    .set_description(""),

    Option("mon_daemon_bytes", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(400ul << 20)
    .set_description(""),

    Option("mon_max_log_entries_per_event", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(4096)
    .set_description(""),

    Option("mon_reweight_min_pgs_per_osd", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(10)
    .set_description(""),

    Option("mon_reweight_min_bytes_per_osd", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(100_M)
    .set_description(""),

    Option("mon_reweight_max_osds", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(4)
    .set_description(""),

    Option("mon_reweight_max_change", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(0.05)
    .set_description(""),

    Option("mon_health_data_update_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(60.0)
    .set_description(""),

    Option("mon_health_to_clog", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("mon_health_to_clog_interval", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1_hr)
    .set_description(""),

    Option("mon_health_to_clog_tick_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(60.0)
    .set_description(""),

    Option("mon_health_preluminous_compat", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description("Include health warnings in preluminous JSON fields"),

    Option("mon_health_preluminous_compat_warning", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description("Warn about the health JSON format change in preluminous JSON fields"),

    Option("mon_health_max_detail", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(50)
    .set_description("max detailed pgs to report in health detail"),

    Option("mon_health_log_update_period", Option::TYPE_INT, Option::LEVEL_DEV)
    .set_default(5)
    .set_description("Minimum time in seconds between log messages about "
                     "each health check")
    .set_min(0),

    Option("mon_data_avail_crit", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(5)
    .set_description(""),

    Option("mon_data_avail_warn", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(30)
    .set_description("issue MON_DISK_LOW health warning when mon available space below this percentage"),

    Option("mon_data_size_warn", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(15_G)
    .set_description(""),

    Option("mon_warn_not_scrubbed", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description(""),

    Option("mon_warn_not_deep_scrubbed", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description(""),

    Option("mon_scrub_interval", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1_day)
    .set_description(""),

    Option("mon_scrub_timeout", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(5_min)
    .set_description(""),

    Option("mon_scrub_max_keys", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(100)
    .set_description(""),

    Option("mon_scrub_inject_crc_mismatch", Option::TYPE_FLOAT, Option::LEVEL_DEV)
    .set_default(0.0)
    .set_description(""),

    Option("mon_scrub_inject_missing_keys", Option::TYPE_FLOAT, Option::LEVEL_DEV)
    .set_default(0.0)
    .set_description(""),

    Option("mon_config_key_max_entry_size", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(4_K)
    .set_description(""),

    Option("mon_sync_timeout", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(60.0)
    .set_description(""),

    Option("mon_sync_max_payload_size", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(1_M)
    .set_description(""),

    Option("mon_sync_debug", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_inject_sync_get_chunk_delay", Option::TYPE_FLOAT, Option::LEVEL_DEV)
    .set_default(0)
    .set_description(""),

    Option("mon_osd_min_down_reporters", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(2)
    .set_description(""),

    Option("mon_osd_reporter_subtree_level", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("host")
    .set_description(""),

    Option("mon_osd_snap_trim_queue_warn_on", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(32768)
    .set_description("Warn when snap trim queue is that large (or larger).")
    .set_long_description("Warn when snap trim queue length for at least one PG crosses this value, as this is indicator of snap trimmer not keeping up, wasting disk space"),

    Option("mon_osd_force_trim_to", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description(""),

    Option("mon_mds_force_trim_to", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description(""),

    Option("mon_mds_skip_sanity", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_fixup_legacy_erasure_code_profiles", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description("Automatically adjust ruleset-* to crush-* so that legacy apps can set modern erasure code profiles without modification"),

    Option("mon_debug_deprecated_as_obsolete", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("mon_debug_dump_transactions", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("mon_debug_dump_json", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("mon_debug_dump_location", Option::TYPE_STR, Option::LEVEL_DEV)
    .set_default("/var/log/ceph/$cluster-$name.tdump")
    .set_description(""),

    Option("mon_debug_no_require_luminous", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("mon_debug_no_require_bluestore_for_ec_overwrites", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("mon_debug_no_initial_persistent_features", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("mon_inject_transaction_delay_max", Option::TYPE_FLOAT, Option::LEVEL_DEV)
    .set_default(10.0)
    .set_description(""),

    Option("mon_inject_transaction_delay_probability", Option::TYPE_FLOAT, Option::LEVEL_DEV)
    .set_default(0)
    .set_description(""),

    Option("mon_sync_provider_kill_at", Option::TYPE_INT, Option::LEVEL_DEV)
    .set_default(0)
    .set_description(""),

    Option("mon_sync_requester_kill_at", Option::TYPE_INT, Option::LEVEL_DEV)
    .set_default(0)
    .set_description(""),

    Option("mon_force_quorum_join", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("mon_keyvaluedb", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("rocksdb")
    .set_description(""),

    Option("mon_debug_unsafe_allow_tier_with_nonempty_snaps", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("mon_osd_blacklist_default_expire", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(1_hr)
    .set_description("Duration in seconds that blacklist entries for clients "
                     "remain in the OSD map"),

    Option("mon_mds_blacklist_interval", Option::TYPE_FLOAT, Option::LEVEL_DEV)
    .set_default(1_day)
    .set_min(1_hr)
    .set_description("Duration in seconds that blacklist entries for MDS "
                     "daemons remain in the OSD map"),

    Option("mon_osd_crush_smoke_test", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("paxos_stash_full_interval", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(25)
    .set_description(""),

    Option("paxos_max_join_drift", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(10)
    .set_description(""),

    Option("paxos_propose_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(1.0)
    .set_description(""),

    Option("paxos_min_wait", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(0.05)
    .set_description(""),

    Option("paxos_min", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(500)
    .set_description(""),

    Option("paxos_trim_min", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(250)
    .set_description(""),

    Option("paxos_trim_max", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(500)
    .set_description(""),

    Option("paxos_service_trim_min", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(250)
    .set_description(""),

    Option("paxos_service_trim_max", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(500)
    .set_description(""),

    Option("paxos_kill_at", Option::TYPE_INT, Option::LEVEL_DEV)
    .set_default(0)
    .set_description(""),

    Option("auth_cluster_required", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("cephx")
    .set_description(""),

    Option("auth_service_required", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("cephx")
    .set_description(""),

    Option("auth_client_required", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("cephx, none")
    .set_description(""),

    Option("auth_supported", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("max_rotating_auth_attempts", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(10)
    .set_description(""),

    Option("cephx_require_signatures", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("cephx_require_version", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1)
    .set_description("Cephx version required (1 = pre-mimic, 2 = mimic+)"),

    Option("cephx_cluster_require_signatures", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("cephx_cluster_require_version", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1)
    .set_description("Cephx version required by the cluster from clients (1 = pre-mimic, 2 = mimic+)"),

    Option("cephx_service_require_signatures", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("cephx_service_require_version", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1)
    .set_description("Cephx version required from ceph services (1 = pre-mimic, 2 = mimic+)"),

    Option("cephx_sign_messages", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("auth_mon_ticket_ttl", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(12_hr)
    .set_description(""),

    Option("auth_service_ticket_ttl", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(1_hr)
    .set_description(""),

    Option("auth_debug", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("mon_client_hunt_parallel", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(2)
    .set_description(""),

    Option("mon_client_hunt_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(3.0)
    .set_description(""),

    Option("mon_client_ping_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(10.0)
    .set_description(""),

    Option("mon_client_ping_timeout", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(30.0)
    .set_description(""),

    Option("mon_client_hunt_interval_backoff", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(2.0)
    .set_description(""),

    Option("mon_client_hunt_interval_min_multiple", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(1.0)
    .set_description(""),

    Option("mon_client_hunt_interval_max_multiple", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(10.0)
    .set_description(""),

    Option("mon_client_max_log_entries_per_message", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1000)
    .set_description(""),

    Option("mon_max_pool_pg_num", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(65536)
    .set_description(""),

    Option("mon_pool_quota_warn_threshold", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description("percent of quota at which to issue warnings")
    .add_service("mgr"),

    Option("mon_pool_quota_crit_threshold", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description("percent of quota at which to issue errors")
    .add_service("mgr"),

    Option("crush_location", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("crush_location_hook", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("")
    .set_description(""),

    Option("crush_location_hook_timeout", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(10)
    .set_description(""),

    Option("objecter_tick_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(5.0)
    .set_description(""),

    Option("objecter_timeout", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(10.0)
    .set_description(""),

    Option("objecter_inflight_op_bytes", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(10000_M)
    .set_description(""),

    Option("objecter_inflight_ops", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(10240)
    .set_description(""),

    Option("objecter_completion_locks_per_session", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(32)
    .set_description(""),

    Option("objecter_inject_no_watch_ping", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("objecter_retry_writes_after_first_reply", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("objecter_debug_inject_relock_delay", Option::TYPE_BOOL, Option::LEVEL_DEV)
    .set_default(false)
    .set_description(""),

    Option("filer_max_purge_ops", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(10)
    .set_description(""),

    Option("filer_max_truncate_ops", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(128)
    .set_description(""),

    Option("journaler_write_head_interval", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(15)
    .set_description(""),

    Option("journaler_prefetch_periods", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(10)
    .set_description(""),

    Option("osd_calc_pg_upmaps_aggressively", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description("try to calculate PG upmaps more aggressively, e.g., "
                     "by doing a fairly exhaustive search of existing PGs "
                     "that can be unmapped or upmapped"),

    Option("osd_calc_pg_upmaps_local_fallback_retries", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(100)
    .set_description("Maximum number of PGs we can attempt to unmap or upmap "
                     "for a specific overfull or underfull osd per iteration "),

    Option("journaler_prezero_periods", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(5)
    .set_description(""),

    Option("osd_check_max_object_name_len_on_startup", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("osd_max_backfills", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(1)
    .set_description("Maximum number of concurrent local and remote backfills or recoveries per OSD ")
    .set_long_description("There can be osd_max_backfills local reservations AND the same remote reservations per OSD. So a value of 1 lets this OSD participate as 1 PG primary in recovery and 1 shard of another recovering PG."),

    Option("osd_min_recovery_priority", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description("Minimum priority below which recovery is not performed"),

    Option("osd_backfill_retry_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(30.0)
    .set_description(""),

    Option("osd_recovery_retry_interval", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(30.0)
    .set_description(""),

    Option("osd_agent_max_ops", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(4)
    .set_description(""),

    Option("osd_agent_max_low_ops", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(2)
    .set_description(""),

    Option("osd_agent_min_evict_effort", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.1)
    .set_description(""),

    Option("osd_agent_quantize_effort", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.1)
    .set_description(""),

    Option("osd_agent_delay_time", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(5.0)
    .set_description(""),

    Option("osd_find_best_info_ignore_history_les", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("osd_agent_hist_halflife", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1000)
    .set_description(""),

    Option("osd_agent_slop", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(.02)
    .set_description(""),

    Option("osd_uuid", Option::TYPE_UUID, Option::LEVEL_ADVANCED)
    .set_default(uuid_d())
    .set_description(""),

    Option("osd_data", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("/var/lib/ceph/osd/$cluster-$id")
    .set_description(""),

    Option("osd_journal", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("/var/lib/ceph/osd/$cluster-$id/journal")
    .set_description(""),

    Option("osd_journal_size", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(5120)
    .set_description(""),

    Option("osd_journal_flush_on_shutdown", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("osd_os_flags", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description(""),

    Option("osd_max_write_size", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(90)
    .set_description(""),

    Option("osd_max_pgls", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(1024)
    .set_description(""),

    Option("osd_client_message_size_cap", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(500_M)
    .set_description(""),

    Option("osd_client_message_cap", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(100)
    .set_description(""),

    Option("osd_pg_bits", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(6)
    .set_description(""),

    Option("osd_pgp_bits", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(6)
    .set_description(""),

    Option("osd_crush_update_weight_set", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("osd_crush_chooseleaf_type", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(1)
    .set_description(""),

    Option("osd_pool_use_gmt_hitset", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("osd_crush_update_on_start", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("osd_class_update_on_start", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("osd_crush_initial_weight", Option::TYPE_FLOAT, Option::LEVEL_ADVANCED)
    .set_default(-1)
    .set_description(""),

    Option("osd_pool_default_crush_rule", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(-1)
    .set_description(""),

    Option("osd_pool_erasure_code_stripe_unit", Option::TYPE_UINT, Option::LEVEL_ADVANCED)
    .set_default(4_K)
    .set_description(""),

    Option("osd_pool_default_size", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(3)
    .set_description(""),

    Option("osd_pool_default_min_size", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description(""),

    Option("osd_pool_default_pg_num", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(8)
    .set_description(""),

    Option("osd_pool_default_pgp_num", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(8)
    .set_description(""),

    Option("osd_pool_default_type", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("replicated")
    .set_description(""),

    Option("osd_pool_default_erasure_code_profile", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("plugin=jerasure technique=reed_sol_van k=2 m=1")
    .set_description(""),

    Option("osd_erasure_code_plugins", Option::TYPE_STR, Option::LEVEL_ADVANCED)
    .set_default("jerasure lrc"
  #ifdef HAVE_BETTER_YASM_ELF64
         " isa"
  #endif
        )
    .set_description(""),

    Option("osd_allow_recovery_below_min_size", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("osd_pool_default_flags", Option::TYPE_INT, Option::LEVEL_ADVANCED)
    .set_default(0)
    .set_description(""),

    Option("osd_pool_default_flag_hashpspool", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(true)
    .set_description(""),

    Option("osd_pool_default_flag_nodelete", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_description(""),

    Option("osd_pool_default_flag_nopgchange", Option::TYPE_BOOL, Option::LEVEL_ADVANCED)
    .set_default(false)
    .set_descript