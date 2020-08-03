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

#ifndef FIFO_QUEUE_H
#define FIFO_QUEUE_H

#include "OpQueue.h"
#include <queue>

#include <boost/intrusive/list.hpp>
#include <boost/intrusive/rbtree.hpp>
#include <boost/intrusive/avl_set.hpp>

//需要完成的函数，具体的说明去OpQueue.h查看
//virtual unsigned length() const = 0; 完成
//virtual void remove_by_class(K k, std::list<T> *out) = 0; 只有prioritizedqueue会用到，暂时不实现
//virtual void enqueue_strict(K cl, unsigned priority, T item) = 0;
//virtual void enqueue_strict_front(K cl, unsigned priority, T item) = 0;
//virtual void enqueue(K cl, unsigned priority, unsigned cost, T item) = 0;
//virtual void enqueue_front(K cl, unsigned priority, unsigned cost, T item) = 0;
//virtual bool empty() const = 0; 完成
//virtual T dequeue() = 0;
//virtual void dump(ceph::Formatter *f) const = 0; 暂时不实现
//virtual ~OpQueue() {}; 没有定义，其他队列也没有定义


//my fifoqueue, T is pair<spg_t,PGQueueable>, K is entity_inst_t 
template <typename T, typename K>
class FifoQueue :  public OpQueue <T, K>
{
  private:
    std::queue<T> myqueue;
  public:
    unsigned my_size;

    FifoQueue(){}

    unsigned length() const final {
      return myqueue.size();
    }
    void remove_by_class(K cl, std::list<T>* removed = 0) final {
        ////maybe to do
    }
    bool empty() const final {
      return myqueue.empty();
    }
    void enqueue_strict(K cl, unsigned p, T item) final {
      myqueue.push(item);
      my_size++;
    }
    void enqueue_strict_front(K cl, unsigned p, T item) final {
      myqueue.push(item);
      my_size++;
    }
    void enqueue(K cl, unsigned p, unsigned cost, T item) final {
      myqueue.push(item);
      my_size++;
    }
    void enqueue_front(K cl, unsigned p, unsigned cost, T item) final {
      myqueue.push(item);
      my_size++;
    }
    T dequeue() override {
      assert(my_size > 0);
      T ret = myqueue.front();
      my_size--;
      myqueue.pop();
      return ret;
    }
    void dump(ceph::Formatter *f) const override {
        //maybe to do
    }
};

#endif
