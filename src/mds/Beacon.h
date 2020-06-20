// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2012 Red Hat
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */


#ifndef BEACON_STATE_H
#define BEACON_STATE_H

#include <boost/utility/string_view.hpp>
#include <mutex>
#include <thread>

#include "include/types.h"
#include "include/Context.h"
#include "msg/Dispatcher.h"
#include "messages/MMDSBeacon.h"

class MonClient;
class MMDSBeacon;
class Message;
class MDSRank;


/**
 * One of these per MDS.  Handle beacon logic in this separate class so
 * that a busy MDS holding its own lock does not hold up sending beacon
 * messages to the mon and cause false lagginess.
 *
 * So that we can continue to operate while the MDS is holding its own lock,
 * we keep copies of the data needed to generate beacon messages.  The MDS is
 * responsible for calling Beacon::notify_* when things change.
 */
class Beacon : public Dispatcher
{
public:
  using clock = ceph::coarse_mono_clock;
  using time = ceph::coarse_mono_time;

  Beacon(CephContext *cct, MonClient *monc, boost::string_view name);
  ~Beacon() override;

  void init(MDSMap const *mdsmap);
  void shutdown();

  bool ms_can_fast_dispatch_any() const override { return true; }
  bool ms_can_fast_dispatch(const Message *m) const override;
  void ms_fast_dispatch(Message *m) override;
  bool ms_dispatch(Message *m) override;
  void ms_handle_connect(Connection *c) override {}
  bool ms_handle_reset(Connection *c) override {return false;}
  void ms_handle_remote_reset(Connection *c) override {}
  bool ms_handle_refused(Connection *c) override {return false;}

  void notify_mdsmap(MDSMap const *mdsmap);
  void notify_health(MDSRank const *mds);

  void handle_mds_beacon(MMDSBeacon *m);
  void send();

  void set_want_state(MDSMap const *mdsmap, MDSMap::DaemonState const newstate);
  MDSMap::DaemonState get_want_state() const;

  /**
   * Send a beacon, and block until the ack is received from the mon
   * or `duration` seconds pass, whichever happens sooner.  Useful
   * for emitting a last message on shutdown.
   */
  void send_and_wait(const double duration);

  bool is_laggy();
  double last_cleared_laggy() const {
    std::unique_lock<std::mutex> lock(mutex);
    return std::chrono::duration<double>(clock::now()-last_laggy).count();
  }

private:
  void _notify_mdsmap(MDSMap const *mdsmap);
  bool _send();

  mutable std::mutex mutex;
  std::thread sender;
  std::condition_variable cvar;
  time last_send = time::min();
  double beacon_interval = 5.0;
  bool finished = false;
  MonClient*    monc;

  // Items we duplicate from the MDS to have access under our own lock
  std::string name;
  version_t epoch = 0;
  CompatSet compat;
  mds_rank_t standby_for_rank = MDS_RANK_NONE;
  std::string standby_for_name;
  fs_cluster_id_t standby_for_fscid = FS_CLUSTER_ID_NONE;
  bool standby_replay = false;
  MDSMap::DaemonState want_state = MDSMap::STATE_BOOT;

  // Internal beacon state
  version_t last_seq = 0; // last seq sent to monitor
  std::map<version_t,time>  seq_stamp;    // seq # -> time sent
  time last_acked_stamp = time::min();  // last time we sent a beacon that got acked
  time last_mon_reconnect = time::min();
  bool laggy = false;
  time last_laggy = time::min();

  // Health status to be copied into each beacon message
  MDSHealth health;
};

#endif // BEACON_STATE_H
