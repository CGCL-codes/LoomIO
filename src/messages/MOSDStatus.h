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

#ifndef CEPH_MOSDSTATUS_H
#define CEPH_MOSDSTATUS_H

#include "msg/Message.h"

class MOSDStatus : public Message {
 public:
  map<int,int> osd_disk_read_time_map; 
  map<int,int> osd_pending_list_size_map;
  map<int,int> osd_pending_list_size_map_write;
  
  MOSDStatus()
    : Message(MSG_OSD_STATUS) {}

private:
  ~MOSDStatus() override {}

public:
  const char *get_type_name() const override { return "osd_status"; }
  void print(ostream& o) const override {
    o << "MOSDStatus";
  }

  void encode_payload(uint64_t features) override {
    ::encode(osd_disk_read_time_map, payload);
    ::encode(osd_pending_list_size_map, payload);
    ::encode(osd_pending_list_size_map_write, payload);
  }
  void decode_payload() override {
    bufferlist::iterator p = payload.begin();
    ::decode(osd_disk_read_time_map, p);
    ::decode(osd_pending_list_size_map, p);
    ::decode(osd_pending_list_size_map_write, p);
  }
};

#endif
