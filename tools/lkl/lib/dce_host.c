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

static void print (const char *str, int len)
{
  va_list args;
  lib_vprintf (str, args);
}

struct lkl_mutex {
  pthread_mutex_t mutex;
};

struct lkl_sem {
#ifdef _POSIX_SEMAPHORES
  sem_t sem;
#else
  pthread_mutex_t lock;
  int count;
  pthread_cond_t cond;
#endif /* _POSIX_SEMAPHORES */
};

struct lkl_tls_key {
  pthread_key_t key;
};

static void panic (void)
{
  dce_panic ();
}

static struct lkl_sem* sem_alloc (int count)
{
  struct lkl_sem *sem;
  sem = lib_malloc (sizeof (*sem));

  if (!sem)
    return NULL;

  if (dce_sem_init (&sem->sem, 1, count) < 0)
  {
    return NULL;
  }

  return sem;
}

static void sem_free (struct lkl_sem *sem)
{
  dce_sem_destroy (&sem->sem);
}

static void sem_up (struct lkl_sem *sem)
{
  dce_sem_post (&sem->sem);
}

static void sem_down (struct lkl_sem *sem)
{
  int err;
  do
  {
    err = dce_sem_wait (&sem->sem);
  } while (err < 0 && errno == EINTR);
}

static struct lkl_mutex *mutex_alloc (int recursive)
{
  struct lkl_mutex *_mutex = malloc(sizeof(struct lkl_mutex));
  pthread_mutex_t *mutex = NULL;
  pthread_mutexattr_t attr;

  if (!_mutex)
    return NULL;

  mutex = &_mutex->mutex;
  WARN_DCE_PTHREAD(dce_pthread_mutexattr_init(&attr));

  if (recursive)
    WARN_DCE_PTHREAD(dce_pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE));

  WARN_DCE_PTHREAD(dce_pthread_mutex_init(mutex, &attr));

  return _mutex;
}

static void mutex_free (struct lkl_mutex *_mutex)
{
  pthread_mutex_t *mutex = &_mutex->mutex;
  WARN_DCE_PTHREAD(dce_pthread_mutex_destroy(mutex));
  lib_free(_mutex);
}

static void mutex_lock (struct lkl_mutex *mutex)
{
  WARN_DCE_PTHREAD(dce_pthread_mutex_lock(&mutex->mutex));
}

static void mutex_unlock (struct lkl_mutex *mutex)
{
  WARN_DCE_PTHREAD(dce_pthread_mutex_unlock(&mutex->mutex));
}

static lkl_thread_t thread_create (void (*fn)(void *), void *arg)
{
  pthread_t thread;
  if (WARN_DCE_PTHREAD(g_dceHandle.pthread_create (g_kernel, &thread, NULL, (void* (*)(void *))fn, arg)))
    return 0;
  else
    return (lkl_thread_t) thread;
}

static void thread_detach (void)
{
	WARN_DCE_PTHREAD(g_dceHandle.pthread_detach (g_kernel, g_dceHandle.pthread_self (g_kernel)));
}

static void thread_exit (void)
{
  g_dceHandle.pthread_exit (g_kernel, NULL);
}

static int thread_join (lkl_thread_t tid)
{
  if (WARN_DCE_PTHREAD(g_dceHandle.pthread_join (g_kernel, (pthread_t) tid, NULL)))
    return -1;
  else
    return 0;
}

static lkl_thread_t thread_self (void)
{
  return (lkl_thread_t) g_dceHandle.pthread_self (g_kernel);
}

static int thread_equal (lkl_thread_t a, lkl_thread_t b)
{
  return pthread_equal((pthread_t)a, (pthread_t)b);
}

static struct lkl_tls_key *tls_alloc (void (*destructor)(void *))
{
	struct lkl_tls_key *ret = g_dceHandle.malloc (g_kernel, sizeof (struct lkl_tls_key));
  if (WARN_DCE_PTHREAD(g_dceHandle.pthread_key_create (g_kernel, &ret->key, destructor)))
  {
    g_dceHandle.free (g_kernel, ret);
    return NULL;
  }
  return ret;
}

static void tls_free (struct lkl_tls_key *key)
{
  WARN_DCE_PTHREAD(g_dceHandle.pthread_key_delete (g_kernel, key->key));
  g_dceHandle.free (g_kernel, key);
}

static int tls_set (struct lkl_tls_key *key, void *data)
{
  if (WARN_DCE_PTHREAD(g_dceHandle.pthread_setspecific (g_kernel, key->key, data)))
    return -1;
  return 0;
}

static void tls_get(struct lkl_tls_key *key)
{
  g_dceHandle.pthread_getspecific (g_kernel, key->key);
}

static void* mem_alloc (unsigned long size)
{
  return g_dceHandle.malloc (g_kernel, (size_t) size);
}

static void mem_free (void * ptr)
{
  g_dceHandle.free (g_kernel, ptr);
}

static unsigned long long time_ns (void)
{
  struct timespec ts;
  /* TODO: check which clk id best suits in DCE */
  g_dceHandle.clock_gettime (g_kernel, CLOCK_MONOTONIC, &ts);
  return 1e9*ts.tv_sec + ts.tv_nsec;
}

static void *timer_alloc (void (*fn)(void *), void *arg)
{
  int err;
  timer_t timer;
  struct sigevent se = {
    .sigev_notify = SIGEV_THREAD,
    .sigev_value = {
      .sival_ptr = arg,
    },
    .sigev_notify_function = (void (*)(union sigval))fn,
  };
  err = g_dceHandle.timer_create (g_kernel, CLOCK_REALTIME, &se, &timer);
  if (err)
    return NULL;
  return (void *)(long) timer;
}

static int timer_set_oneshot (void *_timer, unsigned long ns)
{
  timer_t timer = (timer_t)(long)_timer;
  struct itimerspec ts = {
    .it_value = {
      .tv_sec = ns / 1000000000,
      .tv_nsec = ns % 1000000000,
    },
  };
  return g_dceHandle.timer_settime(g_kernel, timer, 0, &ts, NULL);
}

/*
 * dce_timer_delete not found
 * TODO: try to find workaround
 */
static void timer_free (void *timer)
{
  return;
}

static long _gettid (void)
{
  return (long) g_dceHandle.pthread_self (g_kernel);
}

/*
 * @jmp_buf_set - runs the give function and setups a jump back point by saving
 * the context in the jump buffer; jmp_buf_longjmp can be called from the give
 * function or any callee in that function to return back to the jump back
 * point
 */
static void _jmp_buf_set (struct lkl_jmp_buf *jmpb, void (*f)(void))
{
  return;
}

static void _jmp_buf_longjmp (struct lkl_jmp_buf *jmpb, int val)
{
  return;
}

static void *page_alloc(unsigned long size)
{
	void *addr;

	addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (addr == MAP_FAILED)
		return NULL;

	return addr;
}

static void page_free(void *addr, unsigned long size)
{
	munmap((void *)addr, size);
}

#ifdef LKL_HOST_CONFIG_VFIO_PCI
extern struct lkl_dev_pci_ops vfio_pci_ops;
#endif



struct lkl_host_operations lkl_host_ops = {
  .print = print,
  .panic = panic,
  .sem_alloc = sem_alloc,
  .sem_free = sem_free,
  .sem_up = sem_up,
  .sem_down = sem_down,
  .mutex_alloc = mutex_alloc,
  .mutex_free = mutex_free,
  .mutex_lock = mutex_lock,
  .mutex_unlock = mutex_unlock,
  .thread_create = thread_create,
  .thread_detach = thread_detach,
  .thread_exit = thread_exit,
  .thread_join = thread_join,
  .thread_self = thread_self,
  .thread_equal = thread_equal,
  .tls_alloc = tls_alloc,
  .tls_free = tls_free,
  .tls_set = tls_set,
  .tls_get = tls_get,
  .mem_alloc = mem_alloc,
  .mem_free = mem_free,
  .page_alloc = page_alloc,
	.page_free = page_free,
  .time = time_ns,
  .timer_alloc = timer_alloc,
  .timer_set_oneshot = timer_set_oneshot,
  .timer_free = timer_free,
  .ioremap = lkl_ioremap,
  .iomem_access = lkl_iomem_access,
  .gettid = _gettid,
  .jmp_buf_set = _jmp_buf_set,
  .jmp_buf_longjmp = _jmp_buf_longjmp,
  .memcpy = memcpy,
#ifdef LKL_HOST_CONFIG_VFIO_PCI
	.pci_ops = &vfio_pci_ops,
#endif
};

int parse_mac_str(char *mac_str, __lkl__u8 mac[LKL_ETH_ALEN])
{
	char delim[] = ":";
	char *saveptr = NULL, *token = NULL;
	int i = 0;
	if (!mac_str) {
		return 0;
	}

	for (token = strtok_r(mac_str, delim, &saveptr); i < LKL_ETH_ALEN; i++) {
		if (!token) {
			/* The address is too short */
			return -1;
		} else {
			mac[i] = (__lkl__u8) strtol(token, NULL, 16);
		}

		token = strtok_r(NULL, delim, &saveptr);
	}

	if (strtok_r(NULL, delim, &saveptr)) {
		/* The address is too long */
		return -1;
	}

	return 1;
}

void dce_setup_kernel(void);

void dce_setup_kernel(void){
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

  /*
   * Start the kernel
   */
  //setup_sim_init();
  /*struct lkl_netdev_args nd_args;
  __lkl__u8 mac[LKL_ETH_ALEN] = {0};
  memset(&nd_args, 0, sizeof(struct lkl_netdev_args));
  int offload = strtol("0xc803", NULL, 0);
  static struct lkl_netdev *nd[1];
  nd[0] = lkl_netdev_tap_create("tap7",offload);
  //parse_mac_str("12:34:56:78:9a:bc", mac);
  nd_args.mac = NULL;
  nd_args.offload = offload;
  lkl_netdev_add(nd[0],&nd_args);
  lkl_start_kernel(&lkl_host_ops,"ip=dhcp");*/  

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
