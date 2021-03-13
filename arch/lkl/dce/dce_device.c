#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ethtool.h>
#include <asm/dce_handle_api.h>


struct SimDevice {
  struct net_device dev;
  void *priv;
};

int get_device_ifindex (struct SimDevice *dev);
int lkl_if_set_ipv4(int ifindex, unsigned int addr, unsigned int netmask_len);
int lkl_if_set_mtu(int ifindex, int mtu);
int lkl_if_set_ipv6(int ifindex, void* addr, unsigned int netprefix_len);

static netdev_tx_t
kernel_dev_xmit(struct sk_buff *skb,
    struct net_device *dev)
{
  int err;

  netif_stop_queue(dev);
  if (skb->ip_summed == CHECKSUM_PARTIAL) {
    err = skb_checksum_help(skb);
    if (unlikely(err)) {
      pr_err("checksum error (%d)\n", err);
      return 0;
    }
  }

  lib_dev_xmit((struct SimDevice *)dev, skb->data, skb->len);
  dev_kfree_skb(skb);
  netif_wake_queue(dev);
  return 0;
}

static u32 always_on(struct net_device *dev)
{
  return 1;
}

static const struct ethtool_ops lib_ethtool_ops = {
  .get_link   = always_on,
};

static const struct net_device_ops lib_dev_ops = {
  .ndo_start_xmit   = kernel_dev_xmit,
  .ndo_set_mac_address  = eth_mac_addr,
};

static void lib_dev_setup(struct net_device *dev)
{
  ether_setup(dev);
  dev->mtu                = (16 * 1024) + 20 + 20 + 12;
  dev->hard_header_len    = ETH_HLEN;     /* 14   */
  dev->addr_len           = ETH_ALEN;     /* 6    */
  dev->tx_queue_len       = 0;
  dev->type               = ARPHRD_ETHER;
  dev->flags              = 0;
  /* dev->priv_flags        &= ~IFF_XMIT_DST_RELEASE; */
  dev->features           = 0
          | NETIF_F_HIGHDMA
          | NETIF_F_NETNS_LOCAL;
  /* disabled  NETIF_F_TSO NETIF_F_SG  NETIF_F_FRAGLIST NETIF_F_LLTX */
  dev->ethtool_ops        = &lib_ethtool_ops;
  dev->header_ops         = &eth_header_ops;
  dev->netdev_ops         = &lib_dev_ops;
  dev->needs_free_netdev = false;  // Found in an Open Source Project Patch which fixes the destructor error
  dev->priv_destructor         = &free_netdev;
}

struct SimDevice *dce_dev_create (const char *iface, void *priv, enum SimDevFlags flags)
{
  int err;
  struct SimDevice *dev =
    (struct SimDevice *)alloc_netdev(sizeof(struct SimDevice),
             iface, NET_NAME_UNKNOWN,
             &lib_dev_setup);  
  
  return dev; 
  if (flags & SIM_DEV_NOARP)
    dev->dev.flags |= IFF_NOARP;
  if (flags & SIM_DEV_POINTTOPOINT)
    dev->dev.flags |= IFF_POINTOPOINT;
  if (flags & SIM_DEV_MULTICAST)
    dev->dev.flags |= IFF_MULTICAST;
  if (flags & SIM_DEV_BROADCAST) {
    dev->dev.flags |= IFF_BROADCAST; 
    memset(dev->dev.broadcast, 0xff, 6);
  }
  dev->priv= priv;
  err = register_netdev(&dev->dev);
   
  //lkl_start_kernel(&lkl_host_ops,"");  
  return dev;  
}


void dce_dev_destroy (struct SimDevice *dev)
{
  unregister_netdev(&dev->dev);
  /* XXX */
  free_netdev(&dev->dev);
}

void dce_dev_set_address (struct SimDevice *dev, unsigned char buffer[6])
{
  struct sockaddr sa;

	sa.sa_family = dev->dev.type;
	lib_memcpy(&sa.sa_data, buffer, 6);
	dev->dev.netdev_ops->ndo_set_mac_address(&dev->dev, &sa);

  /*struct sockaddr sa;
  int ifindex = get_device_ifindex (dev); 
  lib_memcpy(&sa.sa_data, buffer, 6);
  if (dev->dev.type == AF_INET)
  {
    lkl_if_set_ipv4 (ifindex, sa, ETH_TLEN);
  }
  else if (dev->dev.type == AF_INET6)
  {
    lkl_if_set_ipv6 (ifindex, sa, ETH_ALEN);
  }
  else
  {
    // Notify dev.type doesn't support
  }*/
}

void dce_dev_set_mtu (struct SimDevice *dev, int mtu)
{
  int ifindex = get_device_ifindex (dev);
  lkl_if_set_mtu (ifindex, mtu);
}

void dce_dev_rx (struct SimDevice *dev, struct SimDevicePacket packet)
{
  struct sk_buff *skb = packet.token;
  struct net_device *device = &dev->dev;

  skb->protocol = eth_type_trans(skb, device);
  skb->ip_summed = CHECKSUM_PARTIAL;

  netif_rx(skb);
}

struct SimDevicePacket dce_dev_create_packet (struct SimDevice *dev, int size)
{
  struct SimDevicePacket packet;
  int len = 1536;
  struct sk_buff *skb = __dev_alloc_skb(len, __GFP_RECLAIM);

  packet.token = skb;
  packet.buffer = skb_put(skb, len);
  return packet;
}

int get_device_ifindex (struct SimDevice *dev)
{
  return dev->dev.ifindex;
}

void *dce_dev_get_private(struct SimDevice *dev)
{
	return dev->priv;
}