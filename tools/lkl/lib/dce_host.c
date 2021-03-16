#include <lkl_host.h>
#include <lkl.h>
#include <dce_init.h>
#include <dce_socket.h>
#include <dce_device.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <poll.h>
#include "iomem.h"
#include "jmp_buf.h"
#include <semaphore.h>
#include "dce_handle_api.h"
#include "dce_sysctl.h"

void setup_sim_init(void);

struct DceHandle g_dceHandle;
struct DceKernel *g_kernel;

static int warn_pthread(int ret, char *str_exp)
{
  if (ret > 0)
    lkl_printf ("%s", str_exp);
  return ret;
}

#define WARN_DCE_PTHREAD(exp) warn_pthread(exp, #exp)

/* 
lkl_host_ops defined previously used semaphore and mutex definitions inside DCE which requireSeparate utilities 
a Thread * instance which is not available while initializing LKL kernel.

Separate utilities can be created for semaphores, mutexes, timers etc. inside the DCE codebase (inspired by posix-host) 
and the lkl_host_ops struct is needed to be intialized by calling lkl_start_kernel. 
*/


struct lkl_host_operations lkl_host_ops;

void dce_setup_kernel(void);

void dce_setup_kernel(void){
  // Setup Kernel 
  // DOES NOT WORK , INCORRECT WAY 
  // CORRECT WAY : https://github.com/ParthPratim/liblkl-test


  fprintf(stderr,"Called lkl_start_kernel\n");
  struct lkl_netdev_args nd_args;
  __lkl__u8 mac[LKL_ETH_ALEN] = {0};
  memset(&nd_args, 0, sizeof(struct lkl_netdev_args));
  int offload = strtol("0xc803", NULL, 0);
  static struct lkl_netdev *nd[1];
  nd[0] = lkl_netdev_tap_create("tap7",offload);
  //parse_mac_str("12:34:56:78:9a:bc", mac);
  nd_args.mac = NULL;
  nd_args.offload = offload;
  //lkl_netdev_add(nd[0],NULL);
  lkl_start_kernel(&lkl_host_ops,"ip=dhcp");
}

void sim_init(struct KernelHandle *kernelHandle, const struct DceHandle *dceHandle, struct DceKernel *kernel)
{
  
  g_dceHandle = *dceHandle;
  g_kernel = kernel;
  #include "kernel_handle_assignment_generated.c"

  kernelHandle->sock_socket = dce_sock_socket;
  kernelHandle->sock_close = dce_sock_close;
  kernelHandle->sock_recvmsg = dce_sock_recvmsg;
  kernelHandle->sock_sendmsg = dce_sock_sendmsg;
  kernelHandle->sock_getsockname = dce_sock_getsockname;
  kernelHandle->sock_getpeername = dce_sock_getpeername;
  kernelHandle->sock_bind = dce_sock_bind;
  kernelHandle->sock_connect = dce_sock_connect;
  kernelHandle->sock_listen = dce_sock_listen;
  kernelHandle->sock_shutdown = dce_sock_shutdown;
  kernelHandle->sock_shutdown = dce_sock_shutdown;
  kernelHandle->sock_accept = dce_sock_accept;
  kernelHandle->sock_ioctl = dce_sock_ioctl;
  kernelHandle->sock_setsockopt = dce_sock_setsockopt;
  kernelHandle->sock_getsockopt = dce_sock_getsockopt;
  kernelHandle->dce_lkl_sysctl = lkl_sysctl;
  kernelHandle->dce_lkl_sysctl_get = lkl_sysctl_get;
  kernelHandle->dev_create = dce_dev_create;
  kernelHandle->dev_destroy = dce_dev_destroy;
  kernelHandle->dev_get_private = dce_dev_get_private;
  kernelHandle->dev_set_address = dce_dev_set_address;
  kernelHandle->dev_set_mtu = dce_dev_set_mtu;
  kernelHandle->dev_rx = dce_dev_rx;
  kernelHandle->dev_create_packet = dce_dev_create_packet;
  kernelHandle->sys_iterate_files = dce_sys_iterate_files;
  kernelHandle->sys_file_read = dce_sys_file_read;
  kernelHandle->sys_file_write = dce_sys_file_write;
  kernelHandle->setup_kernel = dce_setup_kernel;

}

int lib_vprintf(const char *str, va_list args)
{
  return g_dceHandle.vprintf (g_kernel, str, args);
}

void *lib_malloc(unsigned long size)
{
  return g_dceHandle.malloc (g_kernel, size);
}

void lib_free(void *buffer)
{
  g_dceHandle.free (g_kernel, buffer);
}

void *lib_memcpy(void *dst, const void *src, unsigned long size)
{
  return g_dceHandle.memcpy (g_kernel, dst, src, size);
}

void *lib_memset(void *dst, char value, unsigned long size)
{
  return g_dceHandle.memset (g_kernel, dst, value, size);
}

int dce_sem_init (sem_t *sem, int pshared, unsigned int value)
{
  return g_dceHandle.sem_init (g_kernel, sem, pshared, value);
}

void dce_sem_destroy (sem_t *sem)
{
  g_dceHandle.sem_destroy (g_kernel, sem);
}

void dce_sem_post (sem_t *sem)
{
  g_dceHandle.sem_post (g_kernel, sem);
}

int  dce_sem_wait (sem_t *sem)
{
  g_dceHandle.sem_wait (g_kernel, sem);
}

void dce_panic ()
{
  g_dceHandle.panic (g_kernel);
}

int dce_pthread_mutex_init (pthread_mutex_t *mutex, const pthread_mutexattr_t *attribute)
{
  return g_dceHandle.pthread_mutex_init (g_kernel, mutex, attribute);
}

int dce_pthread_mutex_destroy (pthread_mutex_t *mutex)
{
  return g_dceHandle.pthread_mutex_destroy (g_kernel, mutex);
}

int dce_pthread_mutex_lock (pthread_mutex_t *mutex)
{
  return g_dceHandle.pthread_mutex_lock (g_kernel, mutex);
}

int dce_pthread_mutex_unlock (pthread_mutex_t *mutex)
{
  return g_dceHandle.pthread_mutex_unlock (g_kernel, mutex);
}

int dce_pthread_mutexattr_settype (pthread_mutexattr_t *attribute, int  kind)
{
  return g_dceHandle.pthread_mutexattr_settype (g_kernel, attribute, kind);
}

int dce_pthread_mutexattr_init (pthread_mutexattr_t *attr)
{
  return g_dceHandle.pthread_mutexattr_init (g_kernel, attr);
}

void lib_dev_xmit(struct SimDevice *dev, unsigned char *data, int len)
{
	return g_dceHandle.dev_xmit(g_kernel, dev, data, len);
}


static int fd_get_capacity(struct lkl_disk disk, unsigned long long *res)
{
  off_t off;

  off = lseek(disk.fd, 0, SEEK_END);
  if (off < 0)
    return -1;

  *res = off;
  return 0;
}

static int do_rw(ssize_t (*fn)(), struct lkl_disk disk, struct lkl_blk_req *req)
{
  off_t off = req->sector * 512;
  void *addr;
  int len;
  int i;
  int ret = 0;

  for (i = 0; i < req->count; i++) {

    addr = req->buf[i].iov_base;
    len = req->buf[i].iov_len;

    do {
      ret = fn(disk.fd, addr, len, off);

      if (ret <= 0) {
        ret = -1;
        goto out;
      }

      addr += ret;
      len -= ret;
      off += ret;

    } while (len);
  }

out:
  return ret;
}

static int blk_request(struct lkl_disk disk, struct lkl_blk_req *req)
{
  int err = 0;

  switch (req->type) {
  case LKL_DEV_BLK_TYPE_READ:
    err = do_rw(pread, disk, req);
    break;
  case LKL_DEV_BLK_TYPE_WRITE:
    err = do_rw(pwrite, disk, req);
    break;
  case LKL_DEV_BLK_TYPE_FLUSH:
  case LKL_DEV_BLK_TYPE_FLUSH_OUT:
#ifdef __linux__
    err = fdatasync(disk.fd);
#else
    err = fsync(disk.fd);
#endif
    break;
  default:
    return LKL_DEV_BLK_STATUS_UNSUP;
  }

  if (err < 0)
    return LKL_DEV_BLK_STATUS_IOERR;

  return LKL_DEV_BLK_STATUS_OK;
}

struct lkl_dev_blk_ops lkl_dev_blk_ops = {
  .get_capacity = fd_get_capacity,
  .request = blk_request,
};
