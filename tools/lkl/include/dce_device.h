#include <lkl.h>
#include<lkl_host.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/ethtool.h>

struct SimDevice *dce_dev_create (const char *iface, void *priv, enum SimDevFlags flags);

void dce_dev_destroy (struct SimDevice *dev);

void * dce_dev_get_private (struct SimDevice *task);

void dce_dev_set_address (struct SimDevice *dev, unsigned char buffer[6]);

void dce_dev_set_mtu (struct SimDevice *dev, int mtu);

void dce_dev_rx (struct SimDevice *dev, struct SimDevicePacket packet);

struct SimDevicePacket dce_dev_create_packet (struct SimDevice *dev, int size);
