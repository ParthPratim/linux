#ifndef _DCE_SOCKET_H_
#define _DCE_SOCKET_H_

#include <linux/net.h>
#include <linux/errno.h>
#include "dce_init.h"
#include "dce-types.h"
#include <lkl_host.h>

#ifdef __cplusplus
extern "C" {
#endif

int dce_sock_socket (int domain, int type, int protocol, struct DceSocket **socket);

int dce_sock_close (struct DceSocket *socket);

ssize_t dce_sock_recvmsg (struct DceSocket *socket, struct msghdr *msg, int flags);

ssize_t dce_sock_sendmsg (struct DceSocket *socket, const struct msghdr *msg, int flags);

int dce_sock_getsockname (struct DceSocket *socket, struct sockaddr *name, int *namelen);

int dce_sock_getpeername (struct DceSocket *socket, struct sockaddr *name, int *namelen);

int dce_sock_bind (struct DceSocket *socket, const struct sockaddr *name, int namelen);

int dce_sock_connect (struct DceSocket *socket, const struct sockaddr *name, int namelen, int flags);

int dce_sock_listen (struct DceSocket *socket, int backlog);

int dce_sock_shutdown (struct DceSocket *socket, int how);

int dce_sock_accept (struct DceSocket *socket, struct DceSocket **newSocket, int flags);

int dce_sock_ioctl (struct DceSocket *socket, int request, char *argp);

int dce_sock_setsockopt (struct DceSocket *socket, int level, int optname, const void *optval, int optlen);

int dce_sock_getsockopt (struct DceSocket *socket, int level, int optname, void *optval, int *optlen);

#ifdef __cplusplus
}
#endif

#endif /* DCE_SOCKET_SEEN */
