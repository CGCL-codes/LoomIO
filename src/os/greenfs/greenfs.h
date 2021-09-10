#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

	void* greenfs_init(const char*);

	int greenfs_mkfs(void*);

	int greenfs_mount(void*);

	int greenfs_umount(void*, void*);

	void* greenfs_create_collection(void*);

	void* greenfs_open_collection(void*);

	void greenfs_fsync(void*);

	void* greenfs_open(const char*);

	void* greenfs_create(void*, void*, const char*);

	int greenfs_delete(void*, void*, void*);

	int greenfs_write(void*, void*, void*, uint64_t, const char*, uint64_t);

	int greenfs_read(void*, void*, void*, uint64_t, char**, uint64_t);

	int greenfs_status(void*, void*, void*, struct stat*);

#ifdef __cplusplus
}
#endif