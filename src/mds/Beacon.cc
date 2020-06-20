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


#include "common/dout.h"
#include "common/HeartbeatMap.h"

#include "include/stringify.h"
#include "include/util.h"

#include "messages/MMDSBeacon.h"
#include "mon/MonClient.h"
#include "mds/MDLog.h"
#include "mds/MDSRank.h"
#include "mds/MDSMap.h"
#include "mds/Locker.h"

#include "Beacon.h"

#include <math.h>
#include <chrono>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_mds
#undef dout_prefix
#define dout_prefix *_dout << "mds.beacon." << name << ' '

Beacon::Beacon(CephContext *cct, MonClient *monc, boost::string_view name)
  :
    Dispatcher(cct),
    beacon_interval(g_conf->mds_beacon_interval),
    monc(monc),
    name(name)
{
}

Beacon::~Beacon()
{
  shutdown();
}

void Beacon::shutdown()
{
  std::unique_lock<std::mutex> lock(mutex);
  if (!finished) {
    finished = true;
    lock.unlock();
    if (sender.joinable())
      sender.join();
  }
}

void Beacon::init(const MDSMap* mdsmap)
{
  std::unique_lock<std::mutex> lock(mutex);
  assert(mdsmap != NULL);

  _notify_mdsmap(mdsmap);
  standby_for_rank = mds_rank_t(g_conf->mds_standby_for_rank);
  standby_for_name = g_conf->mds_standby_for_name;
  standby_for_fscid = fs_cluster_id_t(g_conf->mds_standby_for_fscid);
  standby_replay = g_conf->mds_standby_replay;

  sender = std::thread([this]() {
    std::unique_lock<std::mutex> lock(mutex);
    std::condition_variable c; // no one wakes us
    while (!finished) {
      auto now = clock::now();
      auto since = std::chrono::duration<double>(now-last_send).count();
      auto interval = beacon_interval;
      if (since >= interval*.90) {
        if (!_send()) {
          interval = 0.5; /* 500ms */
        }
      } else {
        interval -= since;
      }
      dout(20) << "sender thread waiting interval " << interval << "s" << dendl;
      c.wait_for(lock, interval*std::chrono::seconds(1));
    }
  });
}

bool Beacon::ms_can_fast_dispatch(const Message *m) const
{
  return m->get_type() == MSG_MDS_BEACON;
}

void Beacon::ms_fast_dispatch(Message *m)
{
  bool handled = ms_dispatch(m);
  assert(handled);
}

bool Beacon::ms_dispatch(Message *m)
{
  if (m->get_type() == MSG_MDS_BEACON) {
    if (m->get_connection()->get_peer_type() == CEPH_ENTITY_TYPE_MON) {
      handle_mds_beacon(static_cast<MMDSBeacon*>(m));
    } else {
      m->put();
    }
    return true;
  }

  return false;
}


/**
 * Update lagginess state based on response from remote MDSMonitor
 *
 * This function puts the passed message before returning
 */
void Beacon::handle_mds_beacon(MMDSBeacon *m)
{
  std::unique_lock<std::mutex> lock(mutex);
  assert(m != NULL);

  version_t seq = m->get_seq();

  // update lab
  auto it = seq_stamp.find(seq);
  if (it != seq_stamp.end()) {
    auto now = clock::now();

    last_acked_stamp = it->second;
    auto rtt = std::chrono::duration<double>(now - last_acked_stamp).count();

    dout(5) << "received beacon reply " << ceph_mds_state_name(m->get_state()) << " seq " << m->get_seq() << " rtt " << rtt << dendl;

    if (laggy && rtt < g_conf->mds_beacon_grace) {
      dout(0) << " MDS is no longer laggy" << dendl;
      laggy = false;
      last_laggy = now;
    }

    // clean up seq_stamp map
    seq_stamp.erase(seq_stamp.begin(), ++it);

    // Wake a waiter up if present
    cvar.notify_all();
  } else {
    dout(1) << "discarding unexpected beacon reply " << ceph_mds_state_name(m->get_state())
	    << " seq " << m->get_seq() << " dne" << dendl;
  }
  m->put();
}


void Beacon::send()
{
  std::unique_lock<std::mutex> lock(mutex);
  _send();
}


void Beacon::send_and_wait(const double duration)
{
  std::unique_lock<std::mutex> lock(mutex);
  _send();
  auto awaiting_seq = last_seq;
  dout(20) << __func__ << ": awaiting " << awaiting_seq
           << " for up to " << duration << "s" << dendl;

  auto start = clock::now();
  while (!seq_stamp.empty() && seq_stamp.begin()->first <= awaiting_seq) {
    auto now = clock::now();
    auto s = duration*.95-std::chrono::duration<double>(now-start).count();
    if (s < 0) break;
    cvar.wait_for(lock, s*std::chrono::seconds(1));
  }
}


/**
 * Call periodically, or when you have updated the desired state
 */
bool Beacon::_send()
{
  auto now = clock::now();
  auto since = std::chrono::duration<double>(now-last_acked_stamp).count();

  if (!cct->get_heartbeat_map()->is_healthy()) {
    /* If anything isn't progressing, let avoid sending a beacon so that
     * the MDS will consider us laggy */
    dout(0) << "Skipping beacon heartbeat to monitors (last acked " << since << "s ago); MDS internal heartbeat is not healthy!" << dendl;
    return false;
  }

  ++last_seq;
  dout(5) << "Sending beacon " << ceph_mds_state_name(want_state) << " seq " << last_seq << dendl;

  seq_stamp[last_seq] = now;

  assert(want_state != MDSMap::STATE_NULL);
  
  MMDSBeacon *beacon = new MMDSBeacon(
      monc->get_fsid(), mds_gid_t(monc->get_global_id()),
      name,
      epoch,
      want_state,
      last_seq,
      CEPH_FEATURES_SUPPORTED_DEFAULT);

  beacon->set_standby_for_rank(standby_for_rank);
  beacon->set_standby_for_name(standby_for_name);
  beacon->set_standby_for_fscid(standby_for_fscid);
  beacon->set_standby_replay(standby_replay);
  beacon->set_health(health);
  beacon->set_compat(compat);
  // piggyback the sys info on beacon msg
  if (want_state == MDSMap::STATE_BOOT) {
    map<string, string> sys_info;
    collect_sys_info(&sys_info, cct);
    sys_info["addr"] = stringify(monc->get_myaddr());
    beacon->set_sys_info(sys_info);
  }
  monc->send_mon_message(beacon);
  last_send = now;
  return true;
}

/**
 * Call this when there is a new MDSMap available
 */
void Beacon::notify_mdsmap(MDSMap const *mdsmap)
{
  std::unique_lock<std::mutex> lock(mutex);
  assert(mdsmap != NULL);

  _notify_mdsmap(mdsmap);
}

void Beacon::_notify_mdsmap(MDSMap const *mdsmap)
{
  assert(mdsmap != NULL);
  assert(mdsmap->get_epoch() >= epoch);

  if (mdsmap->get_epoch() != epoch) {
    epoch = mdsmap->get_epoch();
    compat = MDSMap::get_compat_set_default();
    compat.merge(mdsmap->compat);
  }
}


bool Beacon::is_laggy()
{
  std::unique_lock<std::mutex> lock(mutex);

  auto now = clock::now();
  auto since = std::chrono::duration<double>(now-last_acked_stamp).count();
  if (since > g_conf->mds_beacon_grace) {
    if (!laggy) {
      dout(1) << "is_laggy " << since << " > " << g_conf->mds_beacon_grace
	      << " since last acked beacon" << dendl;
    }
    laggy = true;
    auto last_reconnect = std::chrono::duration<double>(now-last_mon_reconnect).count();
    if (since > (g_conf->mds_beacon_grace*2) && last_reconnect > g_conf->mds_beacon_interval) {
      // maybe it's not us?
      dout(1) << "initiating monitor reconnect; maybe we're not the slow one"
              << dendl;
      last_mon_reconnect = now;
      monc->reopen_session();
    }
    return true;
  }
  return false;
}

void Beacon::set_want_state(const MDSMap* mdsmap, MDSMap::DaemonState const newstate)
{
  std::unique_lock<std::mutex> lock(mutex);

  // Update mdsmap epoch atomically with updating want_state, so that when
  // we send a beacon with the new want state it has the latest epoch, and
  // once we have updated to the latest epoch, we are not sending out
  // a stale want_state (i.e. one from before making it through MDSMap
  // handling)
  _notify_mdsmap(mdsmap);

  if (want_state != newstate) {
    dout(5) << __func__ << ": "
      << ceph_mds_state_name(want_state) << " -> "
      << ceph_mds_state_name(newstate) << dendl;
    want_state = newstate;
  }
}


/**
 * We are 'shown' an MDS briefly in order to update
 * some health metrics that we will send in the next
 * beacon.
 */
void Beacon::notify_health(MDSRank const *mds)
{
  std::unique_lock<std::mutex> lock(mutex);
  if (!mds) {
    // No MDS rank held
    return;
  }

  // I'm going to touch this MDS, so it must be locked
  assert(mds->mds_lock.is_locked_by_me());

  health.metrics.clear();

  // Detect presence of entries in DamageTable
  if (!mds->damage_table.empty()) {
    MDSHealthMetric m(MDS_HEALTH_DAMAGE, HEALTH_ERR, std::string(
          "Metadata damage detected"));
    health.metrics.push_back(m);
  }

  // Detect MDS_HEALTH_TRIM condition
  // Arbitrary factor of 2, indicates MDS is not trimming promptly
  {
    if (mds->mdlog->get_num_segments() > (size_t)(g_conf->mds_log_max_segments * 2)) {
      std::ostringstream oss;
      oss << "Behind on trimming (" << mds->mdlog->get_num_segments()
        << "/" << g_conf->mds_log_max_segments << ")";

      MDSHealthMetric m(MDS_HEALTH_TRIM, HEALTH_WARN, oss.str());
      m.metadata["num_segments"] = stringify(mds->mdlog->get_num_segments());
      m.metadata["max_segments"] = stringify(g_conf->mds_log_max_segments);
      health.metrics.push_back(m);
    }
  }

  // Detect clients failing to respond to modifications to capabilities in
  // CLIENT_CAPS messages.
  {
    std::list<client_t> late_clients;
    mds->locker->get_late_revoking_clients(&late_clients,
                                           mds->mdsmap->get_session_timeout());
    std::list<MDSHealthMetric> late_cap_metrics;

    for (std::list<client_t>::iterator i = late_clients.begin(); i != late_clients.end(); ++i) {

      // client_t is equivalent to session.info.inst.name.num
      // Construct an entity_name_t to lookup into SessionMap
      entity_name_t ename(CEPH_ENTITY_TYPE_CLIENT, i->v);
      Session const *s = mds->sessionmap.get_session(ename);
      if (s == NULL) {
        // Shouldn't happen, but not worth crashing if it does as this is
        // just health-reporting code.
        derr << "Client ID without session: " << i->v << dendl;
        continue;
      }

      std::ostringstream oss;
      oss << "Client " << s->get_human_name() << " failing to respond to capability release";
      MDSHealthMetric m(MDS_HEALTH_CLIENT_LATE_RELEASE, HEALTH_WARN, oss.str());
      m.metadata["client_id"] = stringify(i->v);
      late_cap_metrics.push_back(m);
    }

    if (late_cap_metrics.size() <= (size_t)g_conf->mds_health_summarize_threshold) {
      health.metrics.splice(health.metrics.end(), late_cap_metrics);
    } else {
      std::ostringstream oss;
      oss << "Many clients (" << late_cap_metrics.size()
          << ") failing to respond to capability release";
      MDSHealthMetric m(MDS_HEALTH_CLIENT_LATE_RELEASE_MANY, HEALTH_WARN, oss.str());
      m.metadata["client_count"] = stringify(late_cap_metrics.size());
      health.metrics.push_back(m);
      late_cap_metrics.clear();
    }
  }

  // Detect clients failing to generate cap releases from CEPH_SESSION_RECALL_STATE
  // messages. May be due to buggy client or resource-hogging application.
  //
  // Detect clients failing to advance their old_client_tid
  {
    set<Session*> sessions;
    mds->sessionmap.get_client_session_set(sessions);

    const auto recall_warning_threshold = g_conf->get_val<uint64_t>("mds_recall_warning_threshold");
    const auto max_completed_requests = g_conf->mds_max_completed_requests;
    const auto max_completed_flushes = g_conf->mds_max_completed_flushes;
    std::list<MDSHealthMetric> late_recall_metrics;
    std::list<MDSHealthMetric> large_completed_requests_metrics;
    for (auto& session : sessions) {
      const uint64_t recall_caps = fmax(0.0, session->get_recall_caps()); /* In Luminous: decay counter may go negative due to hit */
      if (recall_caps > recall_warning_threshold) {
        dout(2) << "Session " << *session <<
             " is not releasing caps fast enough. Recalled caps at " << recall_caps
          << " > " << recall_warning_threshold << " (mds_recall_warning_threshold)." << dendl;
        std::ostringstream oss;
        oss << "Client " << session->get_human_name() << " failing to respond to cache pressure";
        MDSHealthMetric m(MDS_HEALTH_CLIENT_RECALL, HEALTH_WARN, oss.str());
        m.metadata["client_id"] = stringify(session->get_client());
        late_recall_metrics.push_back(m);
      }
      if ((session->get_num_trim_requests_warnings() > 0 &&
	   session->get_num_completed_requests() >= max_completed_requests) ||
	  (session->get_num_trim_flushes_warnings() > 0 &&
	   session->get_num_completed_flushes() >= max_completed_flushes)) {
	std::ostringstream oss;
	oss << "Client " << session->get_human_name() << " failing to advance its oldest client/flush tid. ";
	MDSHealthMetric m(MDS_HEALTH_CLIENT_OLDEST_TID, HEALTH_WARN, oss.str());
	m.metadata["client_id"] = stringify(session->info.inst.name.num());
	large_completed_requests_metrics.push_back(m);
      }
    }

    if (late_recall_metrics.size() <= (size_t)g_conf->mds_health_summarize_threshold) {
      health.metrics.splice(health.metrics.end(), late_recall_metrics);
    } else {
      std::ostringstream oss;
      oss << "Many clients (" << late_recall_metrics.size()
          << ") failing to respond to cache pressure";
      MDSHealthMetric m(MDS_HEALTH_CLIENT_RECALL_MANY, HEALTH_WARN, oss.str());
      m.metadata["client_count"] = stringify(late_recall_metrics.size());
      health.metrics.push_back(m);
      late_recall_metrics.clear();
    }

    if (large_completed_requests_metrics.size() <= (size_t)g_conf->mds_health_summarize_threshold) {
      health.metrics.splice(health.metrics.end(), large_completed_requests_metrics);
    } else {
      std::ostringstream oss;
      oss << "Many clients (" << large_completed_requests_metrics.size()
	<< ") failing to advance their oldest client/flush tid";
      MDSHealthMetric m(MDS_HEALTH_CLIENT_OLDEST_TID_MANY, HEALTH_WARN, oss.str());
      m.metadata["client_count"] = stringify(large_completed_requests_metrics.size());
      health.metrics.push_back(m);
      large_completed_requests_metrics.clear();
    }
  }

  // Detect MDS_HEALTH_SLOW_REQUEST condition
  {
    int slow = mds->get_mds_slow_req_count();
    if (slow) {
      dout(20) << slow << " slow request found" << dendl;
      std::ostringstream oss;
      oss << slow << " slow requests are blocked > " << g_conf->mds_op_complaint_time << " sec";

      MDSHealthMetric m(MDS_HEALTH_SLOW_REQUEST, HEALTH_WARN, oss.str());
      health.metrics.push_back(m);
    }
  }

  {
    auto complaint_time = g_conf->osd_op_complaint_time;
    auto now = clock::now();
    auto cutoff = now - ceph::make_timespan(complaint_time);

    std::string count;
    ceph::coarse_mono_time oldest;
    if (MDSIOContextBase::check_ios_in_flight(cutoff, count, oldest)) {
      dout(20) << count << " slow metadata IOs found" << dendl;

      auto oldest_secs = std::chrono::duration<double>(now - oldest).count();
      std::ostringstream oss;
      oss << count << " slow metadata IOs are blocked > " << complaint_time
	  << " secs, oldest blocked for " << (int64_t)oldest_secs << " secs";

      MDSHealthMetric m(MDS_HEALTH_SLOW_METADATA_IO, HEALTH_WARN, oss.str());
      health.metrics.push_back(m);
    }
  }

  // Report a health warning if we are readonly
  if (mds->mdcache->is_readonly()) {
    MDSHealthMetric m(MDS_HEALTH_READ_ONLY, HEALTH_WARN,
                      "MDS in read-only mode");
    health.metrics.push_back(m);
  }

  // Report if we have significantly exceeded our cache size limit
  if (mds->mdcache->cache_overfull()) {
    std::ostringstream oss;
    oss << "MDS cache is too large (" << bytes2str(mds->mdcache->cache_size())
        << "/" << bytes2str(mds->mdcache->cache_limit_memory()) << "); "
        << mds->mdcache->num_inodes_with_caps << " inodes in use by clients, "
        << mds->mdcache->get_num_strays() << " stray files";

    MDSHealthMetric m(MDS_HEALTH_CACHE_OVERSIZED, HEALTH_WARN, oss.str());
    health.metrics.push_back(m);
  }
}

MDSMap::DaemonState Beacon::get_want_state() const
{
  std::unique_lock<std::mutex> lock(mutex);
  return want_state;
}

