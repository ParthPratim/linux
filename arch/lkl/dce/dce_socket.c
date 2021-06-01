#include <linux/net.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/version.h>
#include <net/sock.h>
#include <linux/file.h>
#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/idr.h>
#include <asm/dce-types.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <net/net_namespace.h>
#include <asm/dce_handle_api.h>
#include <asm/syscalls.h>
#include <stdarg.h>
#include <uapi/asm/unistd.h>
#include <asm/host_ops.h>

#define READ 0
#define WRITE 1

struct DceSocket {};


void setup_sim_init(void);

void setup_sim_init(void){
  rcu_init();

	/* in drivers/base/core.c (called normally by drivers/base/init.c) */
	//devices_init();
	//buses_init();
	//timekeeping_init();
	/* in lib/idr.c (called normally by init/main.c) */
	
	//vfs_caches_init();

	//lib_proc_net_initialize();
  
  /*initcall_t *call;
	extern initcall_t __initcall_start[], __initcall_end[];

	call = __initcall_start;
	do {
		(*call)();
		call++;
	} while (call < __initcall_end);*/
  
}

static struct iovec *copy_iovec(const struct iovec *input, int len)
{
	int size = sizeof(struct iovec) * len;
	struct iovec *output = lib_malloc(size);

	if (!output)
		return NULL;
	lib_memcpy(output, input, size);
	return output;
}

int lkl_call(int nr, int args, ...)
{
	long params[6];
	va_list vl;
	int i;

	va_start(vl, args);
	for (i = 0; i < args; i++)
		params[i] = va_arg(vl, long);
	va_end(vl);
  return lkl_syscall(nr,params);
}

static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct fd f = fdget(fd);
	struct socket *sock;

	*err = -EBADF;
	if (f.file) {
		sock = sock_from_file(f.file, err);
		if (likely(sock)) {
			*fput_needed = f.flags;
			return sock;
		}
		fdput(f);
	}
	return NULL;
}

static int sock_map_fd(struct socket *sock, int flags)
{
	struct file *newfile;
	int fd = get_unused_fd_flags(flags);
	if (unlikely(fd < 0)) {
		sock_release(sock);
		return fd;
	}

	newfile = sock_alloc_file(sock, flags, NULL);
	if (!IS_ERR(newfile)) {
		fd_install(fd, newfile);
		return fd;
	}

	put_unused_fd(fd);
	return PTR_ERR(newfile);
}

static int get_fd(struct socket * kernel_socket){
  int type = kernel_socket->type;
  int flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	type &= SOCK_TYPE_MASK;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

  int fd = sock_map_fd(kernel_socket, flags & (O_CLOEXEC | O_NONBLOCK));  
  return fd;
}

int dce_sock_socket (int domain, int type, int protocol, struct DceSocket **socket)
{
  /*struct socket **kernel_socket = (struct socket **)socket;
  int flags;
  
  flags = type & 0xf;
  if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
    return -EINVAL;
  type &= 0xf;


  int retval = sock_create(domain, type, protocol, kernel_socket);
  struct file *fp = lib_malloc(sizeof(struct file));
  (*kernel_socket)->file = fp;
  fp->f_cred = lib_malloc(sizeof(struct cred));
  return retval;*/


  // LKL ATTEMP 1
  
  struct socket *kernel_socket;
  int err, fput_needed;
  lkl_ops->print("Socket",6);
  int ret = lkl_call(__NR_socket,3,domain,type,protocol);
  if(ret < 0){
    return -1;
  }
  else{
    kernel_socket = sockfd_lookup_light(ret, &err, &fput_needed);
    *socket = (struct DceSocket *) kernel_socket;

    if(kernel_socket->sk->sk_lock.owned)
    lkl_ops->print("sk_lock\n",8);    
    return ret;
  }
  
}

int dce_sock_close (struct DceSocket *socket)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int fd = get_fd(kernel_socket);
  int ret = lkl_call(__NR_close,1,fd);
  
  return ret;
}

ssize_t dce_sock_recvmsg (struct DceSocket *socket, struct msghdr *msg, int flags)
{  
	/*struct socket *kernel_socket = (struct socket *)socket;
	struct msghdr msg_sys;
	struct cmsghdr *user_cmsgh = msg->msg_control;
	size_t user_cmsghlen = msg->msg_controllen;
	int retval;

	msg_sys.msg_name = msg->msg_name;
	msg_sys.msg_namelen = msg->msg_namelen;
	msg_sys.msg_control = msg->msg_control;
	msg_sys.msg_controllen = msg->msg_controllen;
	msg_sys.msg_flags = flags;
    
	iov_iter_init(&msg_sys.msg_iter, READ,
		msg->msg_iter.iov, msg->msg_iter.iov->iov_len, msg->msg_iter.count);

	retval = sock_recvmsg(kernel_socket, &msg_sys , flags);

	msg->msg_name = msg_sys.msg_name;
	msg->msg_namelen = msg_sys.msg_namelen;
	msg->msg_control = user_cmsgh;
	msg->msg_controllen = user_cmsghlen - msg_sys.msg_controllen;
	return retval;*/
  struct socket *kernel_socket = (struct socket *)socket;     
  int fd = get_fd(kernel_socket);
  int ret = lkl_call(__NR_recvmsg,3,fd,msg,flags);
  return ret;
}

ssize_t dce_sock_sendmsg (struct DceSocket *socket, const struct msghdr *msg, int flags)
{
	/*struct socket *kernel_socket = (struct socket *)socket;
	struct iovec *kernel_iov = copy_iovec(msg->msg_iter.iov, msg->msg_iter.iov->iov_len);
	struct msghdr msg_sys;
	int retval;

	msg_sys.msg_name = msg->msg_name;
	msg_sys.msg_namelen = msg->msg_namelen;
	msg_sys.msg_control = msg->msg_control;
	msg_sys.msg_controllen = msg->msg_controllen;
	msg_sys.msg_flags = flags;

	iov_iter_init(&msg_sys.msg_iter, WRITE,
		kernel_iov, msg->msg_iter.iov->iov_len, msg->msg_iter.count);

	retval = sock_sendmsg(kernel_socket, &msg_sys);
	lib_free(kernel_iov);
	return retval;*/
  struct socket *kernel_socket = (struct socket *)socket;     
  int fd = get_fd(kernel_socket);
  int ret = lkl_call(__NR_sendmsg,3,fd,msg,flags);
  return ret;
}

int dce_sock_getsockname (struct DceSocket *socket, struct sockaddr *name, struct socklen_t *namelen)
{
  /*struct socket *kernel_socket = (struct socket *)socket;
  int error = kernel_socket->ops->getname(kernel_socket, name, 0);
  return error;*/
  struct socket *kernel_socket = (struct socket *)socket;     
  int fd = get_fd(kernel_socket);
  int ret = lkl_call(__NR_getsockname,3,fd,name,namelen); 
  return ret;
}

int dce_sock_getpeername (struct DceSocket *socket, struct sockaddr *name, struct socklen_t *namelen)
{
  /*struct socket *kernel_socket = (struct socket *)socket;
  int error = kernel_socket->ops->getname(kernel_socket, name, 1);

  return error;*/
  struct socket *kernel_socket = (struct socket *)socket;     
  int fd = get_fd(kernel_socket);
  int ret = lkl_call(__NR_getpeername,3,fd,name,namelen);
  return ret;
}

int dce_sock_bind (struct DceSocket *socket, const struct sockaddr *name, struct socklen_t * namelen)
{
  /*struct socket * kernel_socket = (struct socket *)socket;
  struct sockaddr_storage address;

  memcpy(&address, name, namelen);
  int error = kernel_socket->ops->bind(kernel_socket, (struct sockaddr *)&address, namelen);
  
  return error;*/
  struct socket *kernel_socket = (struct socket *)socket;     
  int fd = get_fd(kernel_socket);
  struct sockaddr_storage address;
  memcpy(&address, name, namelen);
  int ret = lkl_call(__NR_bind,3,fd,(struct sockaddr *)&address,namelen);
  return ret;
}

int dce_sock_connect (struct DceSocket *socket, const struct sockaddr *name, int namelen, int flags)
{
  /*struct socket *kernel_socket = (struct socket *)socket;
  struct sockaddr_storage address;

  memcpy(&address, name, namelen);

  kernel_socket->file->f_flags = flags;
  int retval = kernel_socket->ops->connect(kernel_socket, (struct sockaddr *)&address,
          namelen, flags);
  return retval;*/

  struct socket *kernel_socket = (struct socket *)socket;     
  kernel_socket->file->f_flags = flags;  
  int fd = get_fd(kernel_socket);
  struct sockaddr_storage address;
  memcpy(&address, name, namelen);  
  int ret = lkl_call(__NR_connect,3,fd,(struct sockaddr *)&address,namelen);
  return ret;
}

int dce_sock_listen (struct DceSocket *socket, int backlog)
{
  /*struct socket * kernel_socket = (struct socket *)socket;
  int error = kernel_socket->ops->listen(kernel_socket, backlog);
  return error;*/
  struct socket *kernel_socket = (struct socket *)socket;       
  int fd = get_fd(kernel_socket);
  int ret = lkl_call(__NR_listen,2,fd,backlog);
  return ret;
}

int dce_sock_shutdown (struct DceSocket *socket, int how)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int retval = kernel_socket->ops->shutdown(kernel_socket, how);
  return retval;
}

int dce_sock_accept (struct DceSocket *socket, struct DceSocket **new_socket,  struct sockaddr *my_addr, struct socklen_t *addrlen, int flags)
{
  /*struct socket *sock, *newsock;
  int err;

  sock = (struct socket *)socket;

  err = sock_create_lite(0, 0, 0, &newsock);
  if (err < 0)
    return err;
  newsock->type = sock->type;
  newsock->ops = sock->ops;

  err = sock->ops->accept(sock, newsock, flags, false);
  if (err < 0) {
    sock_release(newsock);
    return err;
  }
  *new_socket = (struct DceSocket *)newsock;*/

  struct socket *kernel_socket = (struct socket *)socket;     
  struct socket *newsock;
  int err,fput_needed;
  int fd = get_fd(kernel_socket);
  int fd2 = lkl_call(__NR_accept4,4,fd,my_addr,addrlen,flags); 
  newsock = sockfd_lookup_light(fd2, &err, &fput_needed);
  *new_socket = (struct DceSocket *) newsock;

  return fd2;
}

int dce_sock_ioctl (struct DceSocket *socket, int request, char *argp)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int fd = get_fd(kernel_socket);
  int ret = lkl_call(__NR_ioctl,3,fd,request,argp);
  return ret;
}

int dce_sock_setsockopt (struct DceSocket *socket, int level, int optname, const void *optval, int optlen)
{
  /*mm_segment_t oldfs = get_fs();
  struct socket *kernel_socket = (struct socket *)socket;
  char *coptval = (char *)optval;
  int error;
  char *kernel_optval = NULL;
	int err, fput_needed;

  if(kernel_socket->sk->sk_lock.owned)
    lkl_ops->print("sk_lock\n",8);
    
  err = security_socket_setsockopt(kernel_socket, level, optname);

  if (err)
			goto out_put;

		err = BPF_CGROUP_RUN_PROG_SETSOCKOPT(kernel_socket->sk, &level,
						     &optname, optval, &optlen,
						     &kernel_optval);

		if (err < 0) {
			goto out_put;
		} else if (err > 0) {
			err = 0;
			goto out_put;
		}

		if (kernel_optval) {
			set_fs(KERNEL_DS);
			optval = (char __user __force *)kernel_optval;
		}

		if (level == SOL_SOCKET)
			err =
			    sock_setsockopt(kernel_socket, level, optname, optval,
					    optlen);
		else
			err =
			    kernel_socket->ops->setsockopt(kernel_socket, level, optname, optval,
						  optlen);

		if (kernel_optval) {
			set_fs(oldfs);
			kfree(kernel_optval);
		}
out_put:
		fput_light(kernel_socket->file, fput_needed);*/

  /*if (level == SOL_SOCKET){    
    error = sock_setsockopt(kernel_socket, level, optname, coptval,
					    optlen);
  }
  else{    
		error = kernel_socket->ops->setsockopt(kernel_socket, level, optname, coptval,
					    optlen);
  }
  return error;*/
  //return err;
  
  // LKL ATTEMP 1
  struct socket *kernel_socket = (struct socket *)socket;   

  char *coptval = (char *)optval;
  int fd = get_fd(kernel_socket);
  int ret = lkl_call(__NR_setsockopt,5,fd,level,optname,optval,optlen);
  return ret;
}

int dce_sock_getsockopt (struct DceSocket *socket, int level, int optname, void *optval, int *optlen)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int error;
  int fd = get_fd(kernel_socket);
  error = lkl_call(__NR_getsockopt,5,fd, level, optname, optval, optlen);
  return error;
}
