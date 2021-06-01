#ifndef _DCE_INIT_H_
#define _DCE_INIT_H_

#include <lkl.h>
#include "dce-types.h"
#include <stdarg.h>
#include <stdio.h>
#include <linux/types.h>
#include <time.h>
#include <semaphore.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Inspired from net-next-nuse - sim-init.h
 *
 * struct KernelHandle - set of operation handle in LKL
 */

struct KernelHandle {
  /**
   * lkl_kernel_handle_api_generated.h - this file contains
   * the pointer to the functions defined in lkl.h
   * the functionality of every function is document in lkl.h
   */
  #include "lkl_kernel_handle_api_generated.h"

  struct SimTask *(*task_create)(void *priv, unsigned long pid);
  void *(*task_get_private)(struct SimTask *task);

  /**
   * @sock_socket - create a socket
   *
   * @domain - address family
   * @type - semantics of communication
   * @protocol - protocol to be used
   * @socket - pointer to newly created socket
   */
  int (*sock_socket)(int domain, int type, int protocol,
        struct DceSocket **socket);

  /**
   * @sock_close - close the socket and release the resources
   *
   * @socket - pointer to socket
   */
  int (*sock_close)(struct DceSocket *socket);

  /**
   * @sock_recvmsg - receive a message from given socket
   *
   * @socket - receive message form the socket pointed
   *           by socket varaible
   * @msg - pointer to message header struture also
   *        it contians a buffer to store message
   * @flags - type of receiving message
   */
  ssize_t (*sock_recvmsg)(struct DceSocket *socket, struct msghdr *msg,
            int flags);

  /**
   * sock_sendmsg - send a message to the given socket
   *
   * @socket - pointer to socket
   * @msg - pointer to message header structure
   * flags - controls the data sending process
   */
  ssize_t (*sock_sendmsg)(struct DceSocket *socket,
            const struct msghdr *msg, int flags);

  /**
   * @sock_getsockname - get the locally-bound socket name
   *
   * @socket - pointer to the socket whoes name required
   * @name - buffer space to store socket address
   * @namelen - length of the socket address
   */
  int (*sock_getsockname)(struct DceSocket *socket,
        struct sockaddr *name, int *namelen);

  /**
   * @sock_getperrname - get the name of connected peer
   *
   * @socket - pointer to the socket
   * @name - buffer space to store peer socket address
   * @namelen - lenght of the peer socket address
   */
  int (*sock_getpeername)(struct DceSocket *socket, struct sockaddr *name,
        int *namelen);

  /**
   * @sock_bind - binds the given socket to the specified address
   *
   * @socket - bind operation is performed on socket pointed by
               socket variable
   * @name - bind the socket address pointed by name
   * @namelen - length of socket address
   */
  int (*sock_bind)(struct DceSocket *socket, const struct sockaddr *name,
        int namelen);

  /**
   * @sock_connect - initiates a socket connection
   *
   * @socket - pointer to socket
   * @name - pointer to sockaddr structure contains peer's address
   * @namelen - size of sockaddr structure pointed to by name
   * @falgs - indicates non-blocking operations
   */
  int (*sock_connect)(struct DceSocket *socket, const struct sockaddr *name,
        int namelen, int flags);

  /**
   * @sock_listen - put a socket on listing mode to accept connections
   *
   * @socket - pointer to socket
   * @backlog - max limit on pending connection requests
   */
  int (*sock_listen)(struct DceSocket *socket, int backlog);

  /**
   * @sock_shutdown - bring down all or part of a full-duplex connection
   *
   * @socket - pointer to the socket
   * @how - help to select which part of a connection needs to shut down
   *        SHUT_RD: shut down the reception of data
   *        SHUT_WD: shut down the transmission of data
   *        SHUT_RDWR: shut down both reception and trasmission of data
   */
  int (*sock_shutdown)(struct DceSocket *socket, int how);

  /**
   * @sock_accept - accept a new connection request
   *
   * @socket - pointer to the socket on which connection request arrive
   * @newSocket - new socket for future communication
   * flags - file status flag
   */
  int (*sock_accept)(struct DceSocket *socket, struct DceSocket **newSocket,
        struct sockaddr *my_addr, socklen_t *addrlen,
        int flags);

  /**
   * @sock_ioctl - manipulates socket files
   *
   * @socket - pointer to socket
   * @request - request code
   * @argp - arguments corresponds to request code
   */
  int (*sock_ioctl)(struct DceSocket *socket, int request, char *argp);

  /**
   * @sock_setsockopt - set option on socket
   *
   * @socket - pointer to socket
   * @level - protocol level
   * @optname - name of the option
   * @optval - value fo the option
   * @optlen - length of the option value
   */
  int (*sock_setsockopt)(struct DceSocket *socket, int level,
        int optname, const void *optval, int optlen);

  /**
   * @sock_getsockopt - return socket options
   *
   * @socket - pointer to socket
   * @level - protocol level
   * @optname - name of the option
   * optval - buffer to store option value
   * optlen - length of the buffer
   */
  int (*sock_getsockopt)(struct DceSocket *socket, int level,
        int optname, void *optval, int *optlen);

  /**
   * @sock_poll - call poll on socket
   *
   * @socket - pointer to socket
   * @ret - point to kernel poll table
   */
  void (*sock_poll)(struct DceSocket *socket, void *ret);

  /**
   * @sock_pollfreewait - remove entry from poll table
   *
   * @polltable - pointer to poll table
   */
  void (*sock_pollfreewait)(void *polltable);

  /**
   * @dev_create - create a network device and allocates the
   *               resurces
   *
   * @ifname - interface name of network device
   * @priv - pointer to ns3::NetDeivce corresponds to Linux
   *         network device
   * @flags - interface flags
   */
  struct SimDevice *(*dev_create)(const char *ifname, void *priv,
                                  enum SimDevFlags flags);

  /**
   * @dev_destroy - unregister a network device and deallocates
   *                the resources
   *
   * @dev - pointer to network device
   */
  void (*dev_destroy)(struct SimDevice *dev);

  /**
   * @dev_get_private - returns ns3::NetDevice corresponds
   *                    to Linux network device
   *
   * @dev - pointer to network device
   */
  void *(*dev_get_private)(struct SimDevice *dev);

  /**
   * @dev_set_address - set media access control address
   *                    to a network device
   *
   * @dev - pointer to network device
   * @buffer - media access control (MAC) address
   */
  void (*dev_set_address)(struct SimDevice *dev,
         unsigned char buffer[6]);

  /**
   * @dev_set_mtu - change the maximum transmission unit (MTU)
   *                of network device
   *
   * @dev - pointer to network device
   * @mtu - required size of maximum transmission unit (MTU)
   */
  void (*dev_set_mtu)(struct SimDevice *dev, int mtu);

  /**
   * @dev_create_packet - create a packet by allocating new sk_buff
   *
   * @dev - pointer to network device
   * @size - data size of packet (amount of data to add in sk_buff)
   */
  struct SimDevicePacket (*dev_create_packet)(struct SimDevice *dev,
                           int size);

  void (*sys_iterate_files)(const struct SimSysIterator *iter);
  int (*sys_file_read)(const struct SimSysFile *file, char *buffer,
      int size, int offset);
  int (*sys_file_write)(const struct SimSysFile *file,
      const char *buffer, int size, int offset);

  /**
   * @dev_rx - receive a packet on network device
   *
   * @dev - pointer to network device
   * @packet - sk_buff with allocated buffer space for rx packet
   */
  void (*dev_rx)(struct SimDevice *dev, struct SimDevicePacket packet);

  void (*setup_kernel)(void);
};


/**
 * struct DceHandle - set of oprations handle by DCE environemnt
 */
struct DceHandle {
  /**
   * @sem_init - initialize the semaphore
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @sem - pointer to a semaphore
   * @pshared - indicates whether semaphore is sharable
   * @value - initial value of the semaphore
   */
  int (*sem_init) (struct DceKernel *kernel, sem_t *sem, int pshared,
                   unsigned int value);

  /**
   * @sem_destroy - destroy the semaphore
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @sem - pointer to semaphore
   */
  void (*sem_destroy) (struct DceKernel *kernel, sem_t *sem);

  /**
   * @sem_post - increments the semaphore
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @sem - pointer to semaphore
   */
  void (*sem_post) (struct DceKernel *kernel, sem_t *sem);

  /**
   * @sem_wait - decrements the semaphore
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @sem - pointer to semaphore
   */
  void (*sem_wait) (struct DceKernel *kernel, sem_t *sem);

  /**
   * @panic - let DCE know about the kernel panic
              situation.
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   */
  void (*panic) (struct DceKernel *kernel);

  /**
   * @pthread_mutex_init - initalize the mutex
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @mutex - pointer to mutex
   * @attribute - attributes to initalize the mutex
   */
  int  (*pthread_mutex_init) (struct DceKernel *kernel, pthread_mutex_t *mutex,
                              const pthread_mutexattr_t *attribute);

  /**
   * @pthread_mutex_destroy - destroy the mutex
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @mutex - pointer to mutex
   */
  int (*pthread_mutex_destroy) (struct DceKernel *kernel, pthread_mutex_t *mutex);

  /**
   * @pthread_mutex_lock - locks the mutex pointed by mutex
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @mutex - pointer to mutex
   */
  int (*pthread_mutex_lock) (struct DceKernel *kernel, pthread_mutex_t *mutex);

  /**
   * @pthread_mutex_unlock - release the lock on mutex pointed by mutex
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @mutex - pointer to mutex
   */
  int (*pthread_mutex_unlock) (struct DceKernel *kernel, pthread_mutex_t *mutex);

  /**
   * @pthread_mutexattr_settype - set the mutex attribute
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @attribute - pointer to mutex attribute
   * @kind - type of mutex
   */
  int (*pthread_mutexattr_settype) (struct DceKernel *kernel, pthread_mutexattr_t *attribute, int kind);

  /**
   * @pthread_mutexattr_init - initialize the mutex attribute
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @attribute - pointer to mutex attribute
   */
  int (*pthread_mutexattr_init) (struct DceKernel *kernel, pthread_mutexattr_t *attribute);

  /**
   * @vprintf - writes the string pointed by str into a logfile maintain by DCE
   *            using standard vfprinf function
   *
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @str - pointer to c string, may contain embedded format tags.
   * @args - value corresponds to embedded format tags
   */
  int (*vprintf)(struct DceKernel *kernel, const char *str,
                 va_list args);

  /**
   * @malloc - allocates memory in bytes
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @size - size in bytes
   */
  void *(*malloc)(struct DceKernel *kernel, unsigned long size);

  /**
   * @free - release the memory pointed by buffer
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @buffer - pointer to memory location needs to free
   */
  void (*free)(struct DceKernel *kernel, void *buffer);

  /**
   * @memcpy - copy certain number of bytes from one memory location to other
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @dst - pointer to destination memory location
   * @src - pointer to source memory location
   * @size - number of bytes to copy
   */
  void *(*memcpy)(struct DceKernel *kernel, void *dst, const void *src,
                  unsigned long size);

  /**
   * @memset - fills memory with a gvein value
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @dst - pointer to memory location
   * @value - value to fill the memory with
   * @size - number of bytes to fill the memory with the given value starting
   *         from dst
   */
  void *(*memset)(struct DceKernel *kernel, void *dst, char value,
                  unsigned long size);

  /**
   * @atexit - register a function to get a call at normal process termination
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @function - register the function pointed by function varaible
   */
  int (*atexit)(struct DceKernel *kernel, void (*function)(void));

  /**
   * @access - check given file is accessible to calling process
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @pathname - path to file
   * @mode - accessibility checks
   */
  int (*access)(struct DceKernel *kernel, const char *pathname,
                int mode);

  /**
   * @getenv - returns the value corresponds to an environment variable
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @name - name of environment variable
   */
  char *(*getenv)(struct DceKernel *kernel, const char *name);

  /**
   * @mkdir - create a directory
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @pathname - name of directory
   * @mode - permission bits
   */
  int (*mkdir)(struct DceKernel *kernel, const char *pathname,
               mode_t mode);

  /**
   * @open - open a file and returns a file descriptor
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @pathname - name of a file
   * @flags - access modes
   */
  int (*open)(struct DceKernel *kernel, const char *pathname, int flags);

  /**
   * @__fxstat -
   *
   * @kernel -
   * @ver -
   * @fd -
   * @buf -
   */
  int (*__fxstat)(struct DceKernel *kernel, int ver, int fd, void *buf);

  /**
   * @fseek - manipulates the position of file position indicator.
   *          Increments the file position indicator by offset bytes
   *          from the position specified by whence
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @stream - file position indicator
   * @offset - number bytes to increment
   * @whence - position from where offset is added
   */
  int (*fseek)(struct DceKernel *kernel, FILE *stream, long offset,
               int whence);

  /**
   * @setbuf - set the buffer for a stream
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @@stream - pointer to a stream
   * @buf - pointer to buffer
   */
  void (*setbuf)(struct DceKernel *kernel, FILE *stream, char *buf);

  /**
   * @fdopen - associates a stream with an existing FD
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @fd - file descriptor
   * @mode - file mode (must be compatabile with FD)
   */
  FILE *(*fdopen)(struct DceKernel *kernel, int fd, const char *mode);

  /**
   * @ftell - returns the current value of the file position indiciator
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @stream - file poisition indicator
   */
  long (*ftell)(struct DceKernel *kernel, FILE *stream);

  /**
   * @fclose - flushes the stream pointed by the file pointer
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @fp - pointer to stream
   */
  int (*fclose)(struct DceKernel *kernel, FILE *fp);

  /**
   * @fread - read data from a stream
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @ptr - memory location to store the read data
   * @size - read size of bytes at a time
   * @nmemb - number of times size of byte to read
   * @stream - pointer to stream
   */
  size_t (*fread)(struct DceKernel *kernel, void *ptr, size_t size,
                  size_t nmemb, FILE *stream);

  /**
   * @fwrite - writes data to a stream
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @ptr - pointer to data elements to written on stream
   * @size - size of each element
   * @nmemb - number of element
   * stream - pointer to stream
   */
  size_t (*fwrite)(struct DceKernel *kernel, const void *ptr, size_t size,
                   size_t nmemb, FILE *stream);

  /**
   * @random - returns a random number
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   */
  unsigned long (*random)(struct DceKernel *kernel);

  /**
   * @event_schedule_ns - schedule an event
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @ns - event scheduling time
   * @fn - pointer to the function called during the event execution
   * @pre_fn - execute the function pointed by pre_fn before executing fn
   *           when event is scheduled
   */
  void *(*event_schedule_ns)(struct DceKernel *kernel, __u64 ns,
       void (*fn)(void *context), void *context, void (*pre_fn)(void));

  /**
   * @event_cancel - destroy an event
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @event - event identifier
   */
  void (*event_cancel)(struct DceKernel *kernel, void *event);

  /**
   * @current_ns - returns simulator current virtual time
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   */
  __u64 (*current_ns)(struct DceKernel *kernel);

  /**
   * @task_start -
   *
   * @kernel -
   * @callback -
   * @context -
   */
  struct SimTask *(*task_start)(struct DceKernel *kernel,
                                void (*callback)(void *), void *context);

  /**
   * @task_wait -
   *
   * @kernel -
   */
  void (*task_wait)(struct DceKernel *kernel, __u64 ns);

  void (*task_schedule)(void);

  /**
   * @task_current -
   *
   * @kernel -
   */
  struct SimTask *(*task_current)(struct DceKernel *kernel);

  /**
   * @task_wakeup -
   *
   * @kernel -
   * @task -
   */
  int (*task_wakeup)(struct DceKernel *kernel, struct SimTask *task);

  /**
   * @task_yield -
   *
   * @kernel -
   */
  void (*task_yield)(struct DceKernel *kernel);

  /**
   * @dev_xmit - tx operation on ns3::NetDevice
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @dev - pointer to network device
   * @data - pointer to data
   * @len - length of data
   */
  void (*dev_xmit)(struct DceKernel *kernel, struct SimDevice *dev,
                   unsigned char *data, int len);

  /**
   * @signal_raised -
   *
   * @kernel -
   * @task -
   * @sig -
   */
  void (*signal_raised)(struct DceKernel *kernel, struct SimTask *task,
                        int sig);

  /**
   * @poll_event -
   *
   * @flag -
   * @content -
   */
  void (*poll_event)(int flag, void *context);

  /**
   * @pthread_create - initiates a new thread
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @thread_handle - identifier of new thread
   * @attr - attributes use to initialize the thread attirbure (optional)
   * @start_routine - thread will execute function pointed by start_routine
   * @arg - arguments for the start_routine function
   */
  int (*pthread_create) (struct DceKernel *kernel, pthread_t *thread_handle,
                         const pthread_attr_t *attr,
                         void *(*start_routine)(void*), void *arg);

  /**
   * @pthread_detach - put running thread on detach state
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @thread_handle - thread identifier
   */
  int (*pthread_detach) (struct DceKernel *kernel, pthread_t thread_handle);

  /**
   * @pthread_exit - terminates the thread
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @arg - return value
   */
  void (*pthread_exit) (struct DceKernel *kernel, void *arg);

  /**
   * @pthread_join - wait for the termination of target thread
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @thread_handle - thread identifier (target thread)
   * @value_ptr - exit status of target thread
   */
  int (*pthread_join) (struct DceKernel *kernel, pthread_t thread_handle,
                       void **value_ptr);

  /**
   * @pthread_self - returns caller thread ID
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   */
  pthread_t (*pthread_self) (struct DceKernel *kernel);

  /**
   * @pthread_key_create - create thread specific data key
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @key - points to newly created key
   * @destructor - called when thread exits
   */
  int (*pthread_key_create) (struct DceKernel *kernel, pthread_key_t *key,
                             void (*destructor)(void*));

  /**
   * @pthread_key_delete - deletes the thread specific data associated with
   *                       the key
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * key - identify the thread data
   */
  int (*pthread_key_delete) (struct DceKernel *kernel, pthread_key_t key);

  /**
   * @pthread_setspecific - set the data against a key
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @key - data identifier
   * @value - points to data belong to a key
   */
  int (*pthread_setspecific) (struct DceKernel *kernel, pthread_key_t key,
                              const void *value);

  /**
   * @pthread_getspecific - get the data against a key
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @key - data identifier
   */
  void *(*pthread_getspecific) (struct DceKernel *kernel, pthread_key_t key);

  /**
   * @clock_gettime - get the clock time specific clock
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @c - clock ID
   * @tp - a structure contains time in seconds and nanoseconds
   */
  int (*clock_gettime) (struct DceKernel *kernel, clockid_t c,
                        struct timespec *tp);

  /**
   * @timer_create - create a timer
   *
   * @kernel - pointer to the C++ obejct corresponds to ns3::KernelSocketFdFactory
   * @clockid - ID of new timer
   * @sevp - let caller know about timer expire
   * @timerid - time ID
   */
  int (*timer_create) (struct DceKernel *kernel, clockid_t clockid,
                       struct sigevent *sevp, timer_t *timerid);

  /**
   * @timer_settime -
   *
   * @kernel -
   * @fd -
   * @flags -
   * @new_value -
   * @old_value -
   */
  int (*timer_settime) (struct DceKernel *kernel, int fd, int flags,
                        const struct itimerspec *new_value,
                        struct itimerspec *old_value);
};

/* DCE will locate sim_init function after loading lkl library file. */
typedef void (*SimInit)(struct KernelHandle *, const struct DceHandle *,
                        struct DceKernel *kernel);
void sim_init(struct KernelHandle *kernelHandle, const struct DceHandle *dceHandle,
              struct DceKernel *kernel);
#ifdef __cplusplus
}
#endif

#endif /* DCE_INIT_SEEN */
