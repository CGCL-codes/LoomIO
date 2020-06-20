// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "include/compat.h"
#include "mdstypes.h"

#include "mon/MonClient.h"
#include "MDBalancer.h"
#include "MDSRank.h"
#include "MDSMap.h"
#include "CInode.h"
#include "CDir.h"
#include "MDCache.h"
#include "Migrator.h"
#include "Mantle.h"

#include "include/Context.h"
#include "msg/Messenger.h"
#include "messages/MHeartbeat.h"

#include <fstream>
#include <iostream>
#include <vector>
#include <map>
using std::map;
using std::vector;

#include "common/config.h"
#include "common/errno.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_mds
#undef dout_prefix
#define dout_prefix *_dout << "mds." << mds->get_nodeid() << ".bal "
#undef dout
#define dout(lvl) \
  do {\
    auto subsys = ceph_subsys_mds;\
    if ((dout_context)->_conf->subsys.should_gather(ceph_subsys_mds_balancer, lvl)) {\
      subsys = ceph_subsys_mds_balancer;\
    }\
    dout_impl(dout_context, subsys, lvl) dout_prefix
#undef dendl
#define dendl dendl_impl; } while (0)


#define MIN_LOAD    50   //  ??
#define MIN_REEXPORT 5  // will automatically reexport
#define MIN_OFFLOAD 10   // point at which i stop trying, close enough


/* This function DOES put the passed message before returning */
int MDBalancer::proc_message(Message *m)
{
  switch (m->get_type()) {

  case MSG_MDS_HEARTBEAT:
    handle_heartbeat(static_cast<MHeartbeat*>(m));
    break;

  default:
    derr << " balancer unknown message " << m->get_type() << dendl_impl;
    assert(0 == "balancer unknown message");
  }

  return 0;
}

MDBalancer::MDBalancer(MDSRank *m, Messenger *msgr, MonClient *monc) :
    mds(m), messenger(msgr), mon_client(monc)
{
  bal_fragment_interval = g_conf->get_val<int64_t>("mds_bal_fragment_interval");
}

void MDBalancer::handle_conf_change(const struct md_config_t *conf,
				    const std::set <std::string> &changed,
				    const MDSMap &mds_map)
{
  if (changed.count("mds_bal_fragment_interval"))
    bal_fragment_interval = g_conf->get_val<int64_t>("mds_bal_fragment_interval");
}

void MDBalancer::handle_export_pins(void)
{
  auto &q = mds->mdcache->export_pin_queue;
  auto it = q.begin();
  dout(20) << "export_pin_queue size=" << q.size() << dendl;
  while (it != q.end()) {
    auto cur = it++;
    CInode *in = *cur;
    assert(in->is_dir());
    mds_rank_t export_pin = in->get_export_pin(false);

    bool remove = true;
    list<CDir*> dfls;
    in->get_dirfrags(dfls);
    for (auto dir : dfls) {
      if (!dir->is_auth())
	continue;

      if (export_pin == MDS_RANK_NONE) {
	if (dir->state_test(CDir::STATE_AUXSUBTREE)) {
	  if (dir->is_frozen() || dir->is_freezing()) {
	    // try again later
	    remove = false;
	    continue;
	  }
	  dout(10) << " clear auxsubtree on " << *dir << dendl;
	  dir->state_clear(CDir::STATE_AUXSUBTREE);
	  mds->mdcache->try_subtree_merge(dir);
	}
      } else if (export_pin == mds->get_nodeid()) {
	if (dir->state_test(CDir::STATE_CREATING) ||
	    dir->is_frozen() || dir->is_freezing()) {
	  // try again later
	  remove = false;
	  continue;
	}
	if (!dir->is_subtree_root()) {
	  dir->state_set(CDir::STATE_AUXSUBTREE);
	  mds->mdcache->adjust_subtree_auth(dir, mds->get_nodeid());
	  dout(10) << " create aux subtree on " << *dir << dendl;
	} else if (!dir->state_test(CDir::STATE_AUXSUBTREE)) {
	  dout(10) << " set auxsubtree bit on " << *dir << dendl;
	  dir->state_set(CDir::STATE_AUXSUBTREE);
	}
      } else {
	mds->mdcache->migrator->export_dir(dir, export_pin);
	remove = false;
      }
    }

    if (remove) {
      in->state_clear(CInode::STATE_QUEUEDEXPORTPIN);
      q.erase(cur);
    }
  }

  set<CDir *> authsubs;
  mds->mdcache->get_auth_subtrees(authsubs);
  bool print_auth_subtrees = true;

  if (authsubs.size() > AUTH_TREES_THRESHOLD &&
      !g_conf->subsys.should_gather(ceph_subsys_mds, 25)) {
    dout(15) << "number of auth trees = " << authsubs.size() << "; not "
		"printing auth trees" << dendl;
    print_auth_subtrees = false;
  }

  for (auto &cd : authsubs) {
    mds_rank_t export_pin = cd->inode->get_export_pin();

    if (print_auth_subtrees) {
      dout(25) << "auth tree " << *cd << " export_pin=" << export_pin <<
		  dendl;
    }

    if (export_pin >= 0 && export_pin != mds->get_nodeid()) {
      mds->mdcache->migrator->export_dir(cd, export_pin);
    }
  }
}

void MDBalancer::tick()
{
  static int num_bal_times = g_conf->mds_bal_max;
  static utime_t first = ceph_clock_now();
  utime_t now = ceph_clock_now();
  auto bal_interval = g_conf->get_val<int64_t>("mds_bal_interval");
  auto bal_max_until = g_conf->get_val<int64_t>("mds_bal_max_until");

  if (g_conf->mds_bal_export_pin) {
    handle_export_pins();
  }

  // sample?
  if ((double)now - (double)last_sample > g_conf->mds_bal_sample_interval) {
    dout(15) << "tick last_sample now " << now << dendl;
    last_sample = now;
  }

  // balance?
  if (mds->get_nodeid() == 0 &&
      mds->is_active() &&
      bal_interval > 0 &&
      (now - last_heartbeat).sec() >= bal_interval &&
      (num_bal_times ||
       (bal_max_until >= 0 && (now - first).sec() > bal_max_until))) {
    last_heartbeat = now;
    send_heartbeat();
    num_bal_times--;
  }

  mds->mdcache->show_subtrees(10, true);
}




class C_Bal_SendHeartbeat : public MDSInternalContext {
public:
  explicit C_Bal_SendHeartbeat(MDSRank *mds_) : MDSInternalContext(mds_) { }
  void finish(int f) override {
    mds->balancer->send_heartbeat();
  }
};


double mds_load_t::mds_load()
{
  switch(g_conf->mds_bal_mode) {
  case 0:
    return
      .8 * auth.meta_load() +
      .2 * all.meta_load() +
      req_rate +
      10.0 * queue_len;

  case 1:
    return req_rate + 10.0*queue_len;

  case 2:
    return cpu_load_avg;

  }
  ceph_abort();
  return 0;
}

mds_load_t MDBalancer::get_load(utime_t now)
{
  mds_load_t load(now);

  if (mds->mdcache->get_root()) {
    list<CDir*> ls;
    mds->mdcache->get_root()->get_dirfrags(ls);
    for (list<CDir*>::iterator p = ls.begin();
	 p != ls.end();
	 ++p) {
      load.auth.add(now, mds->mdcache->decayrate, (*p)->pop_auth_subtree_nested);
      load.all.add(now, mds->mdcache->decayrate, (*p)->pop_nested);
    }
  } else {
    dout(20) << "get_load no root, no load" << dendl;
  }

  uint64_t num_requests = mds->get_num_requests();

  uint64_t cpu_time = 1;
  {
    string stat_path = PROCPREFIX "/proc/self/stat";
    ifstream stat_file(stat_path);
    if (stat_file.is_open()) {
      vector<string> stat_vec(std::istream_iterator<string>{stat_file},
			      std::istream_iterator<string>());
      if (stat_vec.size() >= 15) {
	// utime + stime
	cpu_time = strtoll(stat_vec[13].c_str(), nullptr, 10) +
		   strtoll(stat_vec[14].c_str(), nullptr, 10);
      } else {
	derr << "input file '" << stat_path << "' not resolvable" << dendl_impl;
      }
    } else {
      derr << "input file '" << stat_path << "' not found" << dendl_impl;
    }
  }

  load.queue_len = messenger->get_dispatch_queue_len();

  bool update_last = true;
  if (last_get_load != utime_t() &&
      now > last_get_load) {
    utime_t el = now;
    el -= last_get_load;
    if (el.sec() >= 1) {
      if (num_requests > last_num_requests)
	load.req_rate = (num_requests - last_num_requests) / (double)el;
      if (cpu_time > last_cpu_time)
	load.cpu_load_avg = (cpu_time - last_cpu_time) / (double)el;
    } else {
      auto p = mds_load.find(mds->get_nodeid());
      if (p != mds_load.end()) {
	load.req_rate = p->second.req_rate;
	load.cpu_load_avg = p->second.cpu_load_avg;
      }
      if (num_requests >= last_num_requests && cpu_time >= last_cpu_time)
	update_last = false;
    }
  }

  if (update_last) {
    last_num_requests = num_requests;
    last_cpu_time = cpu_time;
    last_get_load = now;
  }

  dout(15) << "get_load " << load << dendl;
  return load;
}

/*
 * Read synchronously from RADOS using a timeout. We cannot do daemon-local
 * fallbacks (i.e. kick off async read when we are processing the map and
 * check status when we get here) with the way the mds is structured.
 */
int MDBalancer::localize_balancer()
{
  /* reset everything */
  bool ack = false;
  int r = 0;
  bufferlist lua_src;
  Mutex lock("lock");
  Cond cond;

  /* we assume that balancer is in the metadata pool */
  object_t oid = object_t(mds->mdsmap->get_balancer());
  object_locator_t oloc(mds->mdsmap->get_metadata_pool());
  ceph_tid_t tid = mds->objecter->read(oid, oloc, 0, 0, CEPH_NOSNAP, &lua_src, 0,
                                       new C_SafeCond(&lock, &cond, &ack, &r));
  dout(15) << "launched non-blocking read tid=" << tid
           << " oid=" << oid << " oloc=" << oloc << dendl;

  /* timeout: if we waste half our time waiting for RADOS, then abort! */
  auto bal_interval = g_conf->get_val<int64_t>("mds_bal_interval");
  lock.Lock();
  int ret_t = cond.WaitInterval(lock, utime_t(bal_interval / 2, 0));
  lock.Unlock();

  /* success: store the balancer in memory and set the version. */
  if (!r) {
    if (ret_t == ETIMEDOUT) {
      mds->objecter->op_cancel(tid, -ECANCELED);
      return -ETIMEDOUT;
    }
    bal_code.assign(lua_src.to_str());
    bal_version.assign(oid.name);
    dout(10) << "localized balancer, bal_code=" << bal_code << dendl;
  }
  return r;
}

void MDBalancer::send_heartbeat()
{
  utime_t now = ceph_clock_now();
  
  if (mds->is_cluster_degraded()) {
    dout(10) << "send_heartbeat degraded" << dendl;
    return;
  }

  if (!mds->mdcache->is_open()) {
    dout(5) << "not open" << dendl;
    mds->mdcache->wait_for_open(new C_Bal_SendHeartbeat(mds));
    return;
  }

  if (mds->get_nodeid() == 0) {
    beat_epoch++;
    mds_load.clear();
  }

  // my load
  mds_load_t load = get_load(now);
  mds->logger->set(l_mds_load_cent, 100 * load.mds_load());
  mds->logger->set(l_mds_dispatch_queue_len, load.queue_len);

  mds_load[mds->get_nodeid()] = load;

  // import_map -- how much do i import from whom
  map<mds_rank_t, float> import_map;
  set<CDir*> authsubs;
  mds->mdcache->get_auth_subtrees(authsubs);
  for (set<CDir*>::iterator it = authsubs.begin();
       it != authsubs.end();
       ++it) {
    CDir *im = *it;
    mds_rank_t from = im->inode->authority().first;
    if (from == mds->get_nodeid()) continue;
    if (im->get_inode()->is_stray()) continue;
    import_map[from] += im->pop_auth_subtree.meta_load(now, mds->mdcache->decayrate);
  }
  mds_import_map[ mds->get_nodeid() ] = import_map;


  dout(5) << "mds." << mds->get_nodeid() << " epoch " << beat_epoch << " load " << load << dendl;
  for (map<mds_rank_t, float>::iterator it = import_map.begin();
       it != import_map.end();
       ++it) {
    dout(5) << "  import_map from " << it->first << " -> " << it->second << dendl;
  }


  set<mds_rank_t> up;
  mds->get_mds_map()->get_up_mds_set(up);
  for (set<mds_rank_t>::iterator p = up.begin(); p != up.end(); ++p) {
    if (*p == mds->get_nodeid())
      continue;
    MHeartbeat *hb = new MHeartbeat(load, beat_epoch);
    hb->get_import_map() = import_map;
    messenger->send_message(hb,
                            mds->mdsmap->get_inst(*p));
  }
}

/* This function DOES put the passed message before returning */
void MDBalancer::handle_heartbeat(MHeartbeat *m)
{
  mds_rank_t who = mds_rank_t(m->get_source().num());
  dout(25) << "=== got heartbeat " << m->get_beat() << " from " << m->get_source().num() << " " << m->get_load() << dendl;

  if (!mds->is_active())
    goto out;

  if (!mds->mdcache->is_open()) {
    dout(10) << "opening root on handle_heartbeat" << dendl;
    mds->mdcache->wait_for_open(new C_MDS_RetryMessage(mds, m));
    return;
  }

  if (mds->is_cluster_degraded()) {
    dout(10) << " degraded, ignoring" << dendl;
    goto out;
  }

  if (mds->get_nodeid() != 0 && m->get_beat() > beat_epoch) {
    dout(10) << "receive next epoch " << m->get_beat() << " from mds." << who << " before mds0" << dendl;

    beat_epoch = m->get_beat();
    // clear the mds load info whose epoch is less than beat_epoch 
    mds_load.clear();
  }

  if (who == 0) {
    dout(20) << " from mds0, new epoch " << m->get_beat() << dendl;
    if (beat_epoch != m->get_beat()) {
      beat_epoch = m->get_beat();
      mds_load.clear();
    }

    send_heartbeat();

    mds->mdcache->show_subtrees();
  } else if (mds->get_nodeid() == 0) {
    if (beat_epoch != m->get_beat()) {
      dout(10) << " old heartbeat epoch, ignoring" << dendl;
      goto out;
    }
  }

  mds_load[who] = m->get_load();
  mds_import_map[who] = m->get_import_map();

  {
    unsigned cluster_size = mds->get_mds_map()->get_num_in_mds();
    if (mds_load.size() == cluster_size) {
      // let's go!
      //export_empties();  // no!

      /* avoid spamming ceph -w if user does not turn mantle on */
      if (mds->mdsmap->get_balancer() != "") {
        int r = mantle_prep_rebalance();
        if (!r) goto out;
	mds->clog->warn() << "using old balancer; mantle failed for "
                          << "balancer=" << mds->mdsmap->get_balancer()
                          << " : " << cpp_strerror(r);
      }
      prep_rebalance(m->get_beat());
    }
  }

  // done
 out:
  m->put();
}

double MDBalancer::try_match(balance_state_t& state, mds_rank_t ex, double& maxex,
                             mds_rank_t im, double& maxim)
{
  if (maxex <= 0 || maxim <= 0) return 0.0;

  double howmuch = MIN(maxex, maxim);
  if (howmuch <= 0) return 0.0;

  dout(5) << "   - mds." << ex << " exports " << howmuch << " to mds." << im << dendl;

  if (ex == mds->get_nodeid())
    state.targets[im] += howmuch;

  state.exported[ex] += howmuch;
  state.imported[im] += howmuch;

  maxex -= howmuch;
  maxim -= howmuch;

  return howmuch;
}

void MDBalancer::queue_split(const CDir *dir, bool fast)
{
  dout(10) << __func__ << " enqueuing " << *dir
                       << " (fast=" << fast << ")" << dendl;

  assert(mds->mdsmap->allows_dirfrags());
  const dirfrag_t frag = dir->dirfrag();

  auto callback = [this, frag](int r) {
    if (split_pending.erase(frag) == 0) {
      // Someone beat me to it.  This can happen in the fast splitting
      // path, because we spawn two contexts, one with mds->timer and
      // one with mds->queue_waiter.  The loser can safely just drop
      // out.
      return;
    }

    CDir *split_dir = mds->mdcache->get_dirfrag(frag);
    if (!split_dir) {
      dout(10) << "drop split on " << frag << " because not in cache" << dendl;
      return;
    }
    if (!split_dir->is_auth()) {
      dout(10) << "drop split on " << frag << " because non-auth" << dendl;
      return;
    }

    // Pass on to MDCache: note that the split might still not
    // happen if the checks in MDCache::can_fragment fail.
    dout(10) << __func__ << " splitting " << *split_dir << dendl;
    mds->mdcache->split_dir(split_dir, g_conf->mds_bal_split_bits);
  };

  bool is_new = false;
  if (split_pending.count(frag) == 0) {
    split_pending.insert(frag);
    is_new = true;
  }

  if (fast) {
    // Do the split ASAP: enqueue it in the MDSRank waiters which are
    // run at the end of dispatching the current request
    mds->queue_waiter(new MDSInternalContextWrapper(mds, 
          new FunctionContext(callback)));
  } else if (is_new) {
    // Set a timer to really do the split: we don't do it immediately
    // so that bursts of ops on a directory have a chance to go through
    // before we freeze it.
    mds->timer.add_event_after(bal_fragment_interval,
                               new FunctionContext(callback));
  }
}

void MDBalancer::queue_merge(CDir *dir)
{
  const auto frag = dir->dirfrag();
  auto callback = [this, frag](int r) {
    assert(frag.frag != frag_t());

    // frag must be in this set because only one context is in flight
    // for a given frag at a time (because merge_pending is checked before
    // starting one), and this context is the only one that erases it.
    merge_pending.erase(frag);

    CDir *dir = mds->mdcache->get_dirfrag(frag);
    if (!dir) {
      dout(10) << "drop merge on " << frag << " because not in cache" << dendl;
      return;
    }
    assert(dir->dirfrag() == frag);

    if(!dir->is_auth()) {
      dout(10) << "drop merge on " << *dir << " because lost auth" << dendl;
      return;
    }

    dout(10) << "merging " << *dir << dendl;

    CInode *diri = dir->get_inode();

    frag_t fg = dir->get_frag();
    while (fg != frag_t()) {
      frag_t sibfg = fg.get_sibling();
      list<CDir*> sibs;
      bool complete = diri->get_dirfrags_under(sibfg, sibs);
      if (!complete) {
        dout(10) << "  not all sibs under " << sibfg << " in cache (have " << sibs << ")" << dendl;
        break;
      }
      bool all = true;
      for (list<CDir*>::iterator p = sibs.begin(); p != sibs.end(); ++p) {
        CDir *sib = *p;
        if (!sib->is_auth() || !sib->should_merge()) {
          all = false;
          break;
        }
      }
      if (!all) {
        dout(10) << "  not all sibs under " << sibfg << " " << sibs << " should_merge" << dendl;
        break;
      }
      dout(10) << "  all sibs under " << sibfg << " " << sibs << " should merge" << dendl;
      fg = fg.parent();
    }

    if (fg != dir->get_frag())
      mds->mdcache->merge_dir(diri, fg);
  };

  if (merge_pending.count(frag) == 0) {
    dout(20) << __func__ << " enqueued dir " << *dir << dendl;
    merge_pending.insert(frag);
    mds->timer.add_event_after(bal_fragment_interval,
        new FunctionContext(callback));
  } else {
    dout(20) << __func__ << " dir already in queue " << *dir << dendl;
  }
}

void MDBalancer::prep_rebalance(int beat)
{
  balance_state_t state;

  if (g_conf->mds_thrash_exports) {
    //we're going to randomly export to all the mds in the cluster
    set<mds_rank_t> up_mds;
    mds->get_mds_map()->get_up_mds_set(up_mds);
    for (const auto &rank : up_mds) {
      state.targets[rank] = 0.0;
    }
  } else {
    int cluster_size = mds->get_mds_map()->get_num_in_mds();
    mds_rank_t whoami = mds->get_nodeid();
    rebalance_time = ceph_clock_now();

    dout(5) << " prep_rebalance: cluster loads are" << dendl;

    mds->mdcache->migrator->clear_export_queue();

    // rescale!  turn my mds_load back into meta_load units
    double load_fac = 1.0;
    map<mds_rank_t, mds_load_t>::iterator m = mds_load.find(whoami);
    if ((m != mds_load.end()) && (m->second.mds_load() > 0)) {
      double metald = m->second.auth.meta_load(rebalance_time, mds->mdcache->decayrate);
      double mdsld = m->second.mds_load();
      load_fac = metald / mdsld;
      dout(7) << " load_fac is " << load_fac
	      << " <- " << m->second.auth << " " << metald
	      << " / " << mdsld
	      << dendl;
    }

    mds_meta_load.clear();

    double total_load = 0.0;
    multimap<double,mds_rank_t> load_map;
    for (mds_rank_t i=mds_rank_t(0); i < mds_rank_t(cluster_size); i++) {
      mds_load_t& load = mds_load.at(i);

      double l = load.mds_load() * load_fac;
      mds_meta_load[i] = l;

      if (whoami == 0)
	dout(5) << "  mds." << i
		<< " " << load
		<< " = " << load.mds_load()
		<< " ~ " << l << dendl;

      if (whoami == i) my_load = l;
      total_load += l;

      load_map.insert(pair<double,mds_rank_t>( l, i ));
    }

    // target load
    target_load = total_load / (double)cluster_size;
    dout(5) << "prep_rebalance:  my load " << my_load
	    << "   target " << target_load
	    << "   total " << total_load
	    << dendl;

    // under or over?
    for (auto p : load_map) {
      if (p.first < target_load * (1.0 + g_conf->mds_bal_min_rebalance)) {
	dout(5) << " mds." << p.second << " is underloaded or barely overloaded." << dendl;
	mds_last_epoch_under_map[p.second] = beat_epoch;
      }
    }

    int last_epoch_under = mds_last_epoch_under_map[whoami];
    if (last_epoch_under == beat_epoch) {
      dout(5) << "  i am underloaded or barely overloaded, doing nothing." << dendl;
      return;
    }
    // am i over long enough?
    if (last_epoch_under && beat_epoch - last_epoch_under < 2) {
      dout(5) << "  i am overloaded, but only for " << (beat_epoch - last_epoch_under) << " epochs" << dendl;
      return;
    }

    dout(5) << "  i am sufficiently overloaded" << dendl;


    // first separate exporters and importers
    multimap<double,mds_rank_t> importers;
    multimap<double,mds_rank_t> exporters;
    set<mds_rank_t>             importer_set;
    set<mds_rank_t>             exporter_set;

    for (multimap<double,mds_rank_t>::iterator it = load_map.begin();
	 it != load_map.end();
	 ++it) {
      if (it->first < target_load) {
	dout(15) << "   mds." << it->second << " is importer" << dendl;
	importers.insert(pair<double,mds_rank_t>(it->first,it->second));
	importer_set.insert(it->second);
      } else {
	int mds_last_epoch_under = mds_last_epoch_under_map[it->second];
	if (!(mds_last_epoch_under && beat_epoch - mds_last_epoch_under < 2)) {
	  dout(15) << "   mds." << it->second << " is exporter" << dendl;
	  exporters.insert(pair<double,mds_rank_t>(it->first,it->second));
	  exporter_set.insert(it->second);
	}
      }
    }


    // determine load transfer mapping

    if (true) {
      // analyze import_map; do any matches i can

      dout(15) << "  matching exporters to import sources" << dendl;

      // big -> small exporters
      for (multimap<double,mds_rank_t>::reverse_iterator ex = exporters.rbegin();
	   ex != exporters.rend();
	   ++ex) {
	double maxex = get_maxex(state, ex->second);
	if (maxex <= .001) continue;

	// check importers. for now, just in arbitrary order (no intelligent matching).
	for (map<mds_rank_t, float>::iterator im = mds_import_map[ex->second].begin();
	     im != mds_import_map[ex->second].end();
	     ++im) {
	  double maxim = get_maxim(state, im->first);
	  if (maxim <= .001) continue;
	  try_match(state, ex->second, maxex, im->first, maxim);
	  if (maxex <= .001) break;
	}
      }
    }

    // old way
    if (beat % 2 == 1) {
      dout(15) << "  matching big exporters to big importers" << dendl;
      // big exporters to big importers
      multimap<double,mds_rank_t>::reverse_iterator ex = exporters.rbegin();
      multimap<double,mds_rank_t>::iterator im = importers.begin();
      while (ex != exporters.rend() &&
	     im != importers.end()) {
        double maxex = get_maxex(state, ex->second);
	double maxim = get_maxim(state, im->second);
	if (maxex < .001 || maxim < .001) break;
	try_match(state, ex->second, maxex, im->second, maxim);
	if (maxex <= .001) ++ex;
	if (maxim <= .001) ++im;
      }
    } else { // new way
      dout(15) << "  matching small exporters to big importers" << dendl;
      // small exporters to big importers
      multimap<double,mds_rank_t>::iterator ex = exporters.begin();
      multimap<double,mds_rank_t>::iterator im = importers.begin();
      while (ex != exporters.end() &&
	     im != importers.end()) {
        double maxex = get_maxex(state, ex->second);
	double maxim = get_maxim(state, im->second);
	if (maxex < .001 || maxim < .001) break;
	try_match(state, ex->second, maxex, im->second, maxim);
	if (maxex <= .001) ++ex;
	if (maxim <= .001) ++im;
      }
    }
  }
  try_rebalance(state);
}

int MDBalancer::mantle_prep_rebalance()
{
  balance_state_t state;

  /* refresh balancer if it has changed */
  if (bal_version != mds->mdsmap->get_balancer()) {
    bal_version.assign("");
    int r = localize_balancer();
    if (r) return r;

    /* only spam the cluster log from 1 mds on version changes */
    if (mds->get_nodeid() == 0)
      mds->clog->info() << "mantle balancer version changed: " << bal_version;
  }

  /* prepare for balancing */
  int cluster_size = mds->get_mds_map()->get_num_in_mds();
  rebalance_time = ceph_clock_now();
  mds->mdcache->migrator->clear_export_queue();

  /* fill in the metrics for each mds by grabbing load struct */
  vector < map<string, double> > metrics (cluster_size);
  for (mds_rank_t i=mds_rank_t(0); i < mds_rank_t(cluster_size); i++) {
    mds_load_t& load = mds_load.at(i);

    metrics[i] = {{"auth.meta_load", load.auth.meta_load()},
                  {"all.meta_load", load.all.meta_load()},
                  {"req_rate", load.req_rate},
                  {"queue_len", load.queue_len},
                  {"cpu_load_avg", load.cpu_load_avg}};
  }

  /* execute the balancer */
  Mantle mantle;
  int ret = mantle.balance(bal_code, mds->get_nodeid(), metrics, state.targets);
  dout(5) << " mantle decided that new targets=" << state.targets << dendl;

  /* mantle doesn't know about cluster size, so check target len here */
  if ((int) state.targets.size() != cluster_size)
    return -EINVAL;
  else if (ret)
    return ret;

  try_rebalance(state);
  return 0;
}



void MDBalancer::try_rebalance(balance_state_t& state)
{
  if (g_conf->mds_thrash_exports) {
    dout(5) << "mds_thrash is on; not performing standard rebalance operation!"
	    << dendl;
    return;
  }

  // make a sorted list of my imports
  multimap<double, CDir*> import_pop_map;
  multimap<mds_rank_t, pair<CDir*, double> > import_from_map;
  set<CDir*> fullauthsubs;

  mds->mdcache->get_fullauth_subtrees(fullauthsubs);
  for (auto dir : fullauthsubs) {
    CInode *diri = dir->get_inode();
    if (diri->is_mdsdir())
      continue;
    if (diri->get_export_pin(false) != MDS_RANK_NONE)
      continue;
    if (dir->is_freezing() || dir->is_frozen())
      continue;  // export pbly already in progress

    mds_rank_t from = diri->authority().first;
    double pop = dir->pop_auth_subtree.meta_load(rebalance_time, mds->mdcache->decayrate);
    if (g_conf->mds_bal_idle_threshold > 0 &&
	pop < g_conf->mds_bal_idle_threshold &&
	diri != mds->mdcache->get_root() &&
	from != mds->get_nodeid()) {
      dout(5) << " exporting idle (" << pop << ") import " << *dir
	      << " back to mds." << from << dendl;
      mds->mdcache->migrator->export_dir_nicely(dir, from);
      continue;
    }

    dout(15) << "  map: i imported " << *dir << " from " << from << dendl;
    import_pop_map.insert(make_pair(pop, dir));
    import_from_map.insert(make_pair(from, make_pair(dir, pop)));
  }

  // do my exports!
  map<mds_rank_t, double> export_pop_map;

  for (auto &it : state.targets) {
    mds_rank_t target = it.first;
    double amount = it.second;

    if (amount < MIN_OFFLOAD)
      continue;
    if (amount * 10 * state.targets.size() < target_load)
      continue;

    dout(5) << "want to send " << amount << " to mds." << target
      //<< " .. " << (*it).second << " * " << load_fac
	    << " -> " << amount
	    << dendl;//" .. fudge is " << fudge << dendl;

    double& have = export_pop_map[target];

    mds->mdcache->show_subtrees();

    // search imports from target
    if (import_from_map.count(target)) {
      dout(5) << " aha, looking through imports from target mds." << target << dendl;
      for (auto p = import_from_map.equal_range(target);
	   p.first != p.second; ) {
	CDir *dir = p.first->second.first;
	double pop = p.first->second.second;
	dout(5) << "considering " << *dir << " from " << (*p.first).first << dendl;
	auto plast = p.first++;

	if (dir->inode->is_base())
	  continue;
	assert(dir->inode->authority().first == target);  // cuz that's how i put it in the map, dummy

	if (pop <= amount-have) {
	  dout(5) << "reexporting " << *dir << " pop " << pop
		  << " back to mds." << target << dendl;
	  mds->mdcache->migrator->export_dir_nicely(dir, target);
	  have += pop;
	  import_from_map.erase(plast);
	  for (auto q = import_pop_map.equal_range(pop);
	       q.first != q.second; ) {
	    if (q.first->second == dir) {
	      import_pop_map.erase(q.first);
	      break;
	    }
	    q.first++;
	  }
	} else {
	  dout(5) << "can't reexport " << *dir << ", too big " << pop << dendl;
	}
	if (amount-have < MIN_OFFLOAD)
	  break;
      }
    }
  }

  // any other imports
  for (auto &it : state.targets) {
    mds_rank_t target = it.first;
    double amount = it.second;

    if (!export_pop_map.count(target))
      continue;
    double& have = export_pop_map[target];
    if (amount-have < MIN_OFFLOAD)
      continue;

    for (auto p = import_pop_map.begin();
	 p != import_pop_map.end(); ) {
      CDir *dir = p->second;
      if (dir->inode->is_base()) {
	++p;
	continue;
      }

      double pop = p->first;
      if (pop <= amount-have && pop > MIN_REEXPORT) {
	dout(0) << "reexporting " << *dir << " pop " << pop
		<< " to mds." << target << dendl;
	have += pop;
	mds->mdcache->migrator->export_dir_nicely(dir, target);
	import_pop_map.erase(p++);
      } else {
	++p;
      }
      if (amount-have < MIN_OFFLOAD)
	break;
    }
  }

  set<CDir*> already_exporting;

  for (auto &it : state.targets) {
    mds_rank_t target = it.first;
    double amount = it.second;

    if (!export_pop_map.count(target))
      continue;
    double& have = export_pop_map[target];
    if (amount-have < MIN_OFFLOAD)
      continue;

    // okay, search for fragments of my workload
    list<CDir*> exports;

    for (auto p = import_pop_map.rbegin();
	 p != import_pop_map.rend();
	 ++p) {
      CDir *dir = p->second;
      find_exports(dir, amount, exports, have, already_exporting);
      if (amount-have < MIN_OFFLOAD)
	break;
    }
    //fudge = amount - have;

    for (auto dir : exports) {
      dout(5) << "   - exporting " << dir->pop_auth_subtree
	      << " " << dir->pop_auth_subtree.meta_load(rebalance_time, mds->mdcache->decayrate)
	      << " to mds." << target << " " << *dir << dendl;
      mds->mdcache->migrator->export_dir_nicely(dir, target);
    }
  }

  dout(5) << "rebalance done" << dendl;
  mds->mdcache->show_subtrees();
}

void MDBalancer::find_exports(CDir *dir,
                              double amount,
                              list<CDir*>& exports,
                              double& have,
                              set<CDir*>& already_exporting)
{
  utime_t now = ceph_clock_now();
  if ((double)(now - rebalance_time) > 0.1) {
    derr << " balancer runs too long"  << dendl_impl;
    have = amount;
    return;
  }

  assert(dir->is_auth());

  double need = amount - have;
  if (need < amount * g_conf->mds_bal_min_start)
    return;   // good enough!

  double needmax = need * g_conf->mds_bal_need_max;
  double needmin = need * g_conf->mds_bal_need_min;
  double midchunk = need * g_conf->mds_bal_midchunk;
  double minchunk = need * g_conf->mds_bal_minchunk;

  list<CDir*> bigger_rep, bigger_unrep;
  multimap<double, CDir*> smaller;

  double dir_pop = dir->pop_auth_subtree.meta_load(rebalance_time, mds->mdcache->decayrate);
  dout(7) << " find_exports in " << dir_pop << " " << *dir << " need " << need << " (" << needmin << " - " << needmax << ")" << dendl;

  double subdir_sum = 0;
  for (elist<CInode*>::iterator it = dir->pop_lru_subdirs.begin_use_current();
       !it.end(); ) {
    CInode *in = *it;
    ++it;

    assert(in->is_dir());
    assert(in->get_parent_dir() == dir);

    list<CDir*> dfls;
    in->get_nested_dirfrags(dfls);

    size_t num_idle_frags = 0;
    for (list<CDir*>::iterator p = dfls.begin();
	 p != dfls.end();
	 ++p) {
      CDir *subdir = *p;
      if (already_exporting.count(subdir))
	continue;

      // we know all ancestor dirfrags up to subtree root are not freezing or frozen.
      // It's more efficient to use CDir::is_{freezing,frozen}_tree_root()
      if (subdir->is_frozen_dir() || subdir->is_frozen_tree_root() ||
	  subdir->is_freezing_dir() || subdir->is_freezing_tree_root())
	continue;  // can't export this right now!

      // how popular?
      double pop = subdir->pop_auth_subtree.meta_load(rebalance_time, mds->mdcache->decayrate);
      subdir_sum += pop;
      dout(15) << "   subdir pop " << pop << " " << *subdir << dendl;

      if (pop < minchunk) {
	num_idle_frags++;
	continue;
      }

      // lucky find?
      if (pop > needmin && pop < needmax) {
	exports.push_back(subdir);
	already_exporting.insert(subdir);
	have += pop;
	return;
      }

      if (pop > need) {
	if (subdir->is_rep())
	  bigger_rep.push_back(subdir);
	else
	  bigger_unrep.push_back(subdir);
      } else
	smaller.insert(pair<double,CDir*>(pop, subdir));
    }
    if (dfls.size() == num_idle_frags)
      in->item_pop_lru.remove_myself();
  }
  dout(15) << "   sum " << subdir_sum << " / " << dir_pop << dendl;

  // grab some sufficiently big small items
  multimap<double,CDir*>::reverse_iterator it;
  for (it = smaller.rbegin();
       it != smaller.rend();
       ++it) {

    if ((*it).first < midchunk)
      break;  // try later

    dout(7) << "   taking smaller " << *(*it).second << dendl;

    exports.push_back((*it).second);
    already_exporting.insert((*it).second);
    have += (*it).first;
    if (have > needmin)
      return;
  }

  // apprently not enough; drill deeper into the hierarchy (if non-replicated)
  for (list<CDir*>::iterator it = bigger_unrep.begin();
       it != bigger_unrep.end();
       ++it) {
    dout(15) << "   descending into " << **it << dendl;
    find_exports(*it, amount, exports, have, already_exporting);
    if (have > needmin)
      return;
  }

  // ok fine, use smaller bits
  for (;
       it != smaller.rend();
       ++it) {
    dout(7) << "   taking (much) smaller " << it->first << " " << *(*it).second << dendl;

    exports.push_back((*it).second);
    already_exporting.insert((*it).second);
    have += (*it).first;
    if (have > needmin)
      return;
  }

  // ok fine, drill into replicated dirs
  for (list<CDir*>::iterator it = bigger_rep.begin();
       it != bigger_rep.end();
       ++it) {
    dout(7) << "   descending into replicated " << **it << dendl;
    find_exports(*it, amount, exports, have, already_exporting);
    if (have > needmin)
      return;
  }
}

void MDBalancer::hit_inode(const utime_t& now, CInode *in, int type, int who)
{
  // hit inode
  in->pop.get(type).hit(now, mds->mdcache->decayrate);

  if (in->get_parent_dn())
    hit_dir(now, in->get_parent_dn()->get_dir(), type, who);
}

void MDBalancer::maybe_fragment(CDir *dir, bool hot)
{
  // split/merge
  if (bal_fragment_interval > 0 &&
      dir->is_auth() &&
      !dir->inode->is_base() &&  // not root/base (for now at least)
      !dir->inode->is_stray()) { // not straydir

    // split
    if (g_conf->mds_bal_split_size > 0 &&
	mds->mdsmap->allows_dirfrags() &&
	(dir->should_split() || hot))
    {
      if (split_pending.count(dir->dirfrag()) == 0) {
        queue_split(dir, false);
      } else {
        if (dir->should_split_fast()) {
          queue_split(dir, true);
        } else {
          dout(10) << __func__ << ": fragment already enqueued to split: "
                   << *dir << dendl;
        }
      }
    }

    // merge?
    if (dir->get_frag() != frag_t() && dir->should_merge() &&
	merge_pending.count(dir->dirfrag()) == 0) {
      queue_merge(dir);
    }
  }
}

void MDBalancer::hit_dir(const utime_t& now, CDir *dir, int type, int who, double amount)
{
  // hit me
  double v = dir->pop_me.get(type).hit(now, mds->mdcache->decayrate, amount);

  const bool hot = (v > g_conf->mds_bal_split_rd && type == META_POP_IRD) ||
                   (v > g_conf->mds_bal_split_wr && type == META_POP_IWR);

  dout(20) << "hit_dir " << type << " pop is " << v << ", frag " << dir->get_frag()
           << " size " << dir->get_frag_size() << dendl;

  maybe_fragment(dir, hot);

  // replicate?
  if (type == META_POP_IRD && who >= 0) {
    dir->pop_spread.hit(now, mds->mdcache->decayrate, who);
  }

  double rd_adj = 0.0;
  if (type == META_POP_IRD &&
      dir->last_popularity_sample < last_sample) {
    double dir_pop = dir->pop_auth_subtree.get(type).get(now, mds->mdcache->decayrate);    // hmm??
    dir->last_popularity_sample = last_sample;
    double pop_sp = dir->pop_spread.get(now, mds->mdcache->decayrate);
    dir_pop += pop_sp * 10;

    //if (dir->ino() == inodeno_t(0x10000000002))
    if (pop_sp > 0) {
      dout(20) << "hit_dir " << type << " pop " << dir_pop << " spread " << pop_sp
	      << " " << dir->pop_spread.last[0]
	      << " " << dir->pop_spread.last[1]
	      << " " << dir->pop_spread.last[2]
	      << " " << dir->pop_spread.last[3]
	      << " in " << *dir << dendl;
    }

    if (dir->is_auth() && !dir->is_ambiguous_auth()) {
      if (!dir->is_rep() &&
	  dir_pop >= g_conf->mds_bal_replicate_threshold) {
	// replicate
	double rdp = dir->pop_me.get(META_POP_IRD).get(now, mds->mdcache->decayrate);
	rd_adj = rdp / mds->get_mds_map()->get_num_in_mds() - rdp;
	rd_adj /= 2.0;  // temper somewhat

	dout(5) << "replicating dir " << *dir << " pop " << dir_pop << " .. rdp " << rdp << " adj " << rd_adj << dendl;

	dir->dir_rep = CDir::REP_ALL;
	mds->mdcache->send_dir_updates(dir, true);

	// fixme this should adjust the whole pop hierarchy
	dir->pop_me.get(META_POP_IRD).adjust(rd_adj);
	dir->pop_auth_subtree.get(META_POP_IRD).adjust(rd_adj);
      }

      if (dir->ino() != 1 &&
	  dir->is_rep() &&
	  dir_pop < g_conf->mds_bal_unreplicate_threshold) {
	// unreplicate
	dout(5) << "unreplicating dir " << *dir << " pop " << dir_pop << dendl;

	dir->dir_rep = CDir::REP_NONE;
	mds->mdcache->send_dir_updates(dir);
      }
    }
  }

  // adjust ancestors
  bool hit_subtree = dir->is_auth();         // current auth subtree (if any)
  bool hit_subtree_nested = dir->is_auth();  // all nested auth subtrees

  while (true) {
    CDir *pdir = dir->inode->get_parent_dir();
    dir->pop_nested.get(type).hit(now, mds->mdcache->decayrate, amount);
    if (rd_adj != 0.0)
      dir->pop_nested.get(META_POP_IRD).adjust(now, mds->mdcache->decayrate, rd_adj);

    if (hit_subtree) {
      dir->pop_auth_subtree.get(type).hit(now, mds->mdcache->decayrate, amount);

      if (rd_adj != 0.0)
	dir->pop_auth_subtree.get(META_POP_IRD).adjust(now, mds->mdcache->decayrate, rd_adj);

      if (dir->is_subtree_root())
	hit_subtree = false;                // end of auth domain, stop hitting auth counters.
      else if (pdir)
	pdir->pop_lru_subdirs.push_front(&dir->get_inode()->item_pop_lru);
    }

    if (hit_subtree_nested) {
      dir->pop_auth_subtree_nested.get(type).hit(now, mds->mdcache->decayrate, amount);
      if (rd_adj != 0.0)
	dir->pop_auth_subtree_nested.get(META_POP_IRD).adjust(now, mds->mdcache->decayrate, rd_adj);
    }
    if (!pdir) break;
    dir = pdir;
  }
}


/*
 * subtract off an exported chunk.
 *  this excludes *dir itself (encode_export_dir should have take care of that)
 *  we _just_ do the parents' nested counters.
 *
 * NOTE: call me _after_ forcing *dir into a subtree root,
 *       but _before_ doing the encode_export_dirs.
 */
void MDBalancer::subtract_export(CDir *dir, utime_t now)
{
  dirfrag_load_vec_t subload = dir->pop_auth_subtree;

  while (true) {
    dir = dir->inode->get_parent_dir();
    if (!dir) break;

    dir->pop_nested.sub(now, mds->mdcache->decayrate, subload);
    dir->pop_auth_subtree_nested.sub(now, mds->mdcache->decayrate, subload);
  }
}


void MDBalancer::add_import(CDir *dir, utime_t now)
{
  dirfrag_load_vec_t subload = dir->pop_auth_subtree;

  while (true) {
    dir = dir->inode->get_parent_dir();
    if (!dir) break;

    dir->pop_nested.add(now, mds->mdcache->decayrate, subload);
    dir->pop_auth_subtree_nested.add(now, mds->mdcache->decayrate, subload);
  }
}

void MDBalancer::adjust_pop_for_rename(CDir *pdir, CDir *dir, utime_t now, bool inc)
{
  DecayRate& rate = mds->mdcache->decayrate;

  bool adjust_subtree_nest = dir->is_auth();
  bool adjust_subtree = adjust_subtree_nest && !dir->is_subtree_root();
  CDir *cur = dir;
  while (true) {
    if (inc) {
      pdir->pop_nested.add(now, rate, dir->pop_nested);
      if (adjust_subtree) {
	pdir->pop_auth_subtree.add(now, rate, dir->pop_auth_subtree);
	pdir->pop_lru_subdirs.push_front(&cur->get_inode()->item_pop_lru);
      }

      if (adjust_subtree_nest)
	pdir->pop_auth_subtree_nested.add(now, rate, dir->pop_auth_subtree_nested);
    } else {
      pdir->pop_nested.sub(now, rate, dir->pop_nested);
      if (adjust_subtree)
	pdir->pop_auth_subtree.sub(now, rate, dir->pop_auth_subtree);

      if (adjust_subtree_nest)
	pdir->pop_auth_subtree_nested.sub(now, rate, dir->pop_auth_subtree_nested);
    }

    if (pdir->is_subtree_root())
      adjust_subtree = false;
    cur = pdir;
    pdir = pdir->inode->get_parent_dir();
    if (!pdir) break;
  }
}

void MDBalancer::handle_mds_failure(mds_rank_t who)
{
  if (0 == who) {
    mds_last_epoch_under_map.clear();
  }
}

int MDBalancer::dump_loads(Formatter *f)
{
  utime_t now = ceph_clock_now();
  DecayRate& decayrate = mds->mdcache->decayrate;

  list<CDir*> dfs;
  if (mds->mdcache->get_root()) {
    mds->mdcache->get_root()->get_dirfrags(dfs);
  } else {
    dout(5) << "dump_load no root" << dendl;
  }

  f->open_object_section("loads");

  f->open_array_section("dirfrags");
  while (!dfs.empty()) {
    CDir *dir = dfs.front();
    dfs.pop_front();

    if (f) {
      f->open_object_section("dir");
      dir->dump_load(f, now, decayrate);
      f->close_section();
    }

    for (auto it = dir->begin(); it != dir->end(); ++it) {
      CInode *in = it->second->get_linkage()->get_inode();
      if (!in || !in->is_dir())
	continue;

      list<CDir*> ls;
      in->get_dirfrags(ls);
      for (auto subdir : ls) {
	if (subdir->pop_nested.meta_load() < .001)
	  continue;
	dfs.push_back(subdir);
      }
    }
  }
  f->close_section();  // dirfrags array

  f->open_object_section("mds_load");
  {

    auto dump_mds_load = [f, now](mds_load_t& load) {
      f->dump_float("request_rate", load.req_rate);
      f->dump_float("cache_hit_rate", load.cache_hit_rate);
      f->dump_float("queue_length", load.queue_len);
      f->dump_float("cpu_load", load.cpu_load_avg);
      f->dump_float("mds_load", load.mds_load());

      DecayRate rate; // no decay
      f->open_object_section("auth_dirfrags");
      load.auth.dump(f, now, rate);
      f->close_section();
      f->open_object_section("all_dirfrags");
      load.all.dump(f, now, rate);
      f->close_section();
    };

    for (auto p : mds_load) {
      stringstream name;
      name << "mds." << p.first;
      f->open_object_section(name.str().c_str());
      dump_mds_load(p.second);
      f->close_section();
    }
  }
  f->close_section(); // mds_load

  f->open_object_section("mds_meta_load");
  for (auto p : mds_meta_load) {
    stringstream name;
    name << "mds." << p.first;
    f->dump_float(name.str().c_str(), p.second);
  }
  f->close_section(); // mds_meta_load

  f->open_object_section("mds_import_map");
  for (auto p : mds_import_map) {
    stringstream name1;
    name1 << "mds." << p.first;
    f->open_array_section(name1.str().c_str());
    for (auto q : p.second) {
      f->open_object_section("from");
      stringstream name2;
      name2 << "mds." << q.first;
      f->dump_float(name2.str().c_str(), q.second);
      f->close_section();
    }
    f->close_section(); // mds.? array
  }
  f->close_section(); // mds_import_map

  f->close_section(); // loads
  return 0;
}
