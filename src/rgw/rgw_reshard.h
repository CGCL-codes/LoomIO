// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef RGW_RESHARD_H
#define RGW_RESHARD_H

#include <vector>
#include <functional>

#include "include/rados/librados.hpp"
#include "common/ceph_time.h"
#include "cls/rgw/cls_rgw_types.h"
#include "cls/lock/cls_lock_client.h"
#include "rgw_bucket.h"


class CephContext;
class RGWRados;

class RGWBucketReshardLock {
  using Clock = ceph::coarse_mono_clock;

  RGWRados* store;
  const std::string lock_oid;
  const bool ephemeral;
  rados::cls::lock::Lock internal_lock;
  std::chrono::seconds duration;

  Clock::time_point start_time;
  Clock::time_point renew_thresh;

  void reset_time(const Clock::time_point& now) {
    start_time = now;
    renew_thresh = start_time + duration / 2;
  }

public:
  RGWBucketReshardLock(RGWRados* _store,
		       const std::string& reshard_lock_oid,
		       bool _ephemeral);
  RGWBucketReshardLock(RGWRados* _store,
		       const RGWBucketInfo& bucket_info,
		       bool _ephemeral) :
    RGWBucketReshardLock(_store, bucket_info.bucket.get_key(':'), _ephemeral)
  {}

  int lock();
  void unlock();
  int renew(const Clock::time_point&);

  bool should_renew(const Clock::time_point& now) const {
    return now >= renew_thresh;
  }
}; // class RGWBucketReshardLock

class RGWBucketReshard {
public:

  friend class RGWReshard;

  using Clock = ceph::coarse_mono_clock;

private:

  RGWRados *store;
  RGWBucketInfo bucket_info;
  std::map<string, bufferlist> bucket_attrs;

  RGWBucketReshardLock reshard_lock;
  RGWBucketReshardLock* outer_reshard_lock;

  int create_new_bucket_instance(int new_num_shards,
				 RGWBucketInfo& new_bucket_info);
  int do_reshard(int num_shards,
		 RGWBucketInfo& new_bucket_info,
		 int max_entries,
                 bool verbose,
                 ostream *os,
		 Formatter *formatter);
public:

  // pass nullptr for the final parameter if no outer reshard lock to
  // manage
  RGWBucketReshard(RGWRados *_store, const RGWBucketInfo& _bucket_info,
                   const std::map<string, bufferlist>& _bucket_attrs,
		   RGWBucketReshardLock* _outer_reshard_lock);
  int execute(int num_shards, int max_op_entries,
              bool verbose = false, ostream *out = nullptr,
              Formatter *formatter = nullptr,
	      RGWReshard *reshard_log = nullptr);
  int get_status(std::list<cls_rgw_bucket_instance_entry> *status);
  int cancel();
  static int clear_resharding(RGWRados* store,
			      const RGWBucketInfo& bucket_info);
  int clear_resharding() {
    return clear_resharding(store, bucket_info);
  }
  static int clear_index_shard_reshard_status(RGWRados* store,
					      const RGWBucketInfo& bucket_info);
  int clear_index_shard_reshard_status() {
    return clear_index_shard_reshard_status(store, bucket_info);
  }
  static int set_resharding_status(RGWRados* store,
				   const RGWBucketInfo& bucket_info,
				   const string& new_instance_id,
				   int32_t num_shards,
				   cls_rgw_reshard_status status);
  int set_resharding_status(const string& new_instance_id,
			    int32_t num_shards,
			    cls_rgw_reshard_status status) {
    return set_resharding_status(store, bucket_info,
				 new_instance_id, num_shards, status);
  }
}; // RGWBucketReshard

class RGWReshard {
public:
    using Clock = ceph::coarse_mono_clock;

private:
    RGWRados *store;
    string lock_name;
    rados::cls::lock::Lock instance_lock;
    int num_logshards;

    bool verbose;
    ostream *out;
    Formatter *formatter;

    void get_logshard_oid(int shard_num, string *shard);
protected:
  class ReshardWorker : public Thread {
    CephContext *cct;
    RGWReshard *reshard;
    Mutex lock;
    Cond cond;

  public:
    ReshardWorker(CephContext * const _cct,
		              RGWReshard * const _reshard)
      : cct(_cct),
        reshard(_reshard),
        lock("ReshardWorker") {
    }

    void *entry() override;
    void stop();
  };

  ReshardWorker *worker = nullptr;
  std::atomic<bool> down_flag = { false };

  string get_logshard_key(const string& tenant, const string& bucket_name);
  void get_bucket_logshard_oid(const string& tenant, const string& bucket_name, string *oid);

public:
  RGWReshard(RGWRados* _store, bool _verbose = false, ostream *_out = nullptr, Formatter *_formatter = nullptr);
  int add(cls_rgw_reshard_entry& entry);
  int update(const RGWBucketInfo& bucket_info, const RGWBucketInfo& new_bucket_info);
  int get(cls_rgw_reshard_entry& entry);
  int remove(cls_rgw_reshard_entry& entry);
  int list(int logshard_num, string& marker, uint32_t max, std::list<cls_rgw_reshard_entry>& entries, bool *is_truncated);
  int clear_bucket_resharding(const string& bucket_instance_oid, cls_rgw_reshard_entry& entry);

  /* reshard thread */
  int process_single_logshard(int logshard_num);
  int process_all_logshards();
  bool going_down();
  void start_processor();
  void stop_processor();
};


class RGWReshardWait {
  RGWRados *store;
  Mutex lock{"RGWReshardWait::lock"};
  Cond cond;

  bool going_down{false};

  int do_wait();
public:
  RGWReshardWait(RGWRados *_store) : store(_store) {}
  ~RGWReshardWait() {
    assert(going_down);
  }
  int block_while_resharding(RGWRados::BucketShard *bs,
			     string *new_bucket_id,
			     const RGWBucketInfo& bucket_info);

  void stop() {
    Mutex::Locker l(lock);
    going_down = true;
    cond.SignalAll();
  }
};

#endif
