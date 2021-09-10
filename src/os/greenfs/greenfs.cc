#include <stdio.h>
#include <string.h>

#include "os/ObjectStore.h"
#include "os/bluestore/BlueStore.h"
#include "global/global_init.h"

#include "common/strtol.h"
#include "common/ceph_argparse.h"

#include "greenfs.h"

boost::intrusive_ptr<ceph::common::CephContext> cct;

typedef struct BSColl
{
    coll_t cid;
    ObjectStore::CollectionHandle ch;
} BSColl;

#ifdef __cplusplus
extern "C" {
#endif

// BlueStore operations

void *greenfs_init(const char* path) {
    vector<const char*> args;
    ObjectStore* store;
    cct = global_init(nullptr, args, CEPH_ENTITY_TYPE_OSD, CODE_ENVIRONMENT_UTILITY, CINIT_FLAG_NO_MON_CONFIG);
    common_init_finish(g_ceph_context);
    store = ObjectStore::create(g_ceph_context, string("bluestore"), string(path), string("store_temp_journal"));
    return (void *)store;
}

int greenfs_mkfs(void* store) {
    ObjectStore* ostore = (ObjectStore *)store;
    return ostore->mkfs();
}

int greenfs_mount(void* store) {
    ObjectStore* ostore = (ObjectStore *)store;
    return ostore->mount();
}

int greenfs_umount(void* store, void* bscoll) {
    ObjectStore* ostore = (ObjectStore *)store;
    BSColl* coll = (BSColl *)bscoll;
    int ret = 0;
    if (ostore != NULL){
        coll->ch.reset();
        ret = ostore->umount();
    }
    delete coll;
    return ret;
}

// Collection operations

void *greenfs_create_collection(void* store) {
    ObjectStore* ostore = (ObjectStore *)store;
    BSColl* coll = new BSColl;
    coll->cid = coll_t();
    coll->ch = ostore->create_new_collection(coll->cid);
    {
        BlueStore::Transaction t;
        t.create_collection(coll->cid, 0);
        ostore->queue_transaction(coll->ch, std::move(t));
    }
    return (void *)coll;
}

void *greenfs_open_collection(void* store) {
    ObjectStore* ostore = (ObjectStore *)store;
    BSColl* coll = new BSColl;
    coll->cid = coll_t();
    coll->ch = ostore->open_collection(coll->cid);
    return (void *)coll;
}

void greenfs_fsync(void* bscoll) {
    BSColl* coll = (BSColl *)bscoll;
    coll->ch->flush();
}

// File operations

void *greenfs_open(const char* name) {
    ghobject_t *obj = new ghobject_t(hobject_t(sobject_t(string(name), CEPH_NOSNAP)));
    return (void *)obj;
}

void *greenfs_create(void* store, void* bscoll, const char* name) {
    ObjectStore* ostore = (ObjectStore *)store;
    BSColl* coll = (BSColl *)bscoll;
    ghobject_t *obj = new ghobject_t(hobject_t(sobject_t(string(name), CEPH_NOSNAP)));
    ObjectStore::Transaction t;
    t.touch(coll->cid, *obj);
    ostore->queue_transaction(coll->ch, std::move(t));
    return (void *)obj;
}

int greenfs_delete(void* store, void* bscoll, void* object) {
    ObjectStore* ostore = (ObjectStore *)store;
    BSColl* coll = (BSColl *)bscoll;
    ghobject_t* obj = (ghobject_t *)object;
    ObjectStore::Transaction t;
    t.remove(coll->cid, *obj);
    return ostore->queue_transaction(coll->ch, std::move(t));
}

int greenfs_write(void* store, void* bscoll, void* object, uint64_t offset, const char* data, uint64_t length) {
    ObjectStore* ostore = (ObjectStore *)store;
    BSColl* coll = (BSColl *)bscoll;
    ghobject_t* obj = (ghobject_t *)object;
    ObjectStore::Transaction t;
    bufferlist bl;
    bl.append(data, length);
    t.write(coll->cid, *obj, offset, bl.length(), bl);
    ostore->queue_transaction(coll->ch, std::move(t));
    return bl.length();
}

int greenfs_read(void* store, void* bscoll, void* object, uint64_t offset, char** data_read, uint64_t length) {
    ObjectStore* ostore = (ObjectStore *)store;
    BSColl* coll = (BSColl *)bscoll;
    ghobject_t* obj = (ghobject_t *)object;
    bufferlist readback;
    int ret = ostore->read(coll->ch, *obj, offset, length, readback);
    *data_read = readback.c_str();
    return ret;
}

int greenfs_status(void* store, void* bscoll, void* object, struct stat* st) {
    ObjectStore* ostore = (ObjectStore *)store;
    BSColl* coll = (BSColl *)bscoll;
    ghobject_t* obj = (ghobject_t *)object;
    return ostore->stat(coll->ch, *obj, st);
}

#ifdef __cplusplus
}
#endif