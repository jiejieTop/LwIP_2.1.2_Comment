/**
 * @file
 * This is the IPv4 layer implementation for incoming and outgoing IP traffic.
 *
 * @see ip_frag.c
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"

#if LWIP_IPV4

#include "lwip/ip.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/ip4_frag.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/igmp.h"
#include "lwip/priv/raw_priv.h"
#include "lwip/udp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/autoip.h"
#include "lwip/stats.h"
#include "lwip/prot/iana.h"

#include <string.h>

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

/** Set this to 0 in the rare case of wanting to call an extra function to
 * generate the IP checksum (in contrast to calculating it on-the-fly). */
#ifndef LWIP_INLINE_IP_CHKSUM
#if LWIP_CHECKSUM_CTRL_PER_NETIF
#define LWIP_INLINE_IP_CHKSUM   0
#else /* LWIP_CHECKSUM_CTRL_PER_NETIF */
#define LWIP_INLINE_IP_CHKSUM   1
#endif /* LWIP_CHECKSUM_CTRL_PER_NETIF */
#endif

#if LWIP_INLINE_IP_CHKSUM && CHECKSUM_GEN_IP
#define CHECKSUM_GEN_IP_INLINE  1
#else
#define CHECKSUM_GEN_IP_INLINE  0
#endif

#if LWIP_DHCP || defined(LWIP_IP_ACCEPT_UDP_PORT)
#define IP_ACCEPT_LINK_LAYER_ADDRESSING 1

/** Some defines for DHCP to let link-layer-addressed packets through while the
 * netif is down.
 * To use this in your own application/protocol, define LWIP_IP_ACCEPT_UDP_PORT(port)
 * to return 1 if the port is accepted and 0 if the port is not accepted.
 */
#if LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT)
/* accept DHCP client port and custom port */
#define IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(port) (((port) == PP_NTOHS(LWIP_IANA_PORT_DHCP_CLIENT)) \
         || (LWIP_IP_ACCEPT_UDP_PORT(port)))
#elif defined(LWIP_IP_ACCEPT_UDP_PORT) /* LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT) */
/* accept custom port only */
#define IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(port) (LWIP_IP_ACCEPT_UDP_PORT(port))
#else /* LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT) */
/* accept DHCP client port only */
#define IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(port) ((port) == PP_NTOHS(LWIP_IANA_PORT_DHCP_CLIENT))
#endif /* LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT) */

#else /* LWIP_DHCP */
#define IP_ACCEPT_LINK_LAYER_ADDRESSING 0
#endif /* LWIP_DHCP */

/** The IP header ID of the next outgoing IP packet */
static u16_t ip_id;

#if LWIP_MULTICAST_TX_OPTIONS
/**用于多播的默认netif */
static struct netif *ip4_default_multicast_netif;

/**
 * @ingroup ip4
 * 为IPv4多播设置默认netif */
void
ip4_set_default_multicast_netif(struct netif *default_multicast_netif)
{
  ip4_default_multicast_netif = default_multicast_netif;
}
#endif /* LWIP_MULTICAST_TX_OPTIONS */

#ifdef LWIP_HOOK_IP4_ROUTE_SRC
/**
 * Source based IPv4 routing must be fully implemented in
 * LWIP_HOOK_IP4_ROUTE_SRC(). This function only provides the parameters.
 */
struct netif *
ip4_route_src(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  if (src != NULL) {
    /* when src==NULL, the hook is called from ip4_route(dest) */
    struct netif *netif = LWIP_HOOK_IP4_ROUTE_SRC(src, dest);
    if (netif != NULL) {
      return netif;
    }
  }
  return ip4_route(dest);
}
#endif /* LWIP_HOOK_IP4_ROUTE_SRC */


/**
 *为给定的IP地址查找适当的网络接口。
 *它搜索网络接口列表。找到匹配项
 *
 *@param dest 要查找路由的目标IP地址
 *@return 发送到达目的地的网卡 netif
 */ 
struct netif *
ip4_route(const ip4_addr_t *dest)
{
#if !LWIP_SINGLE_NETIF
  struct netif *netif;

  LWIP_ASSERT_CORE_LOCKED();

#if LWIP_MULTICAST_TX_OPTIONS
  /*默认使用管理选择的接口进行多播*/
  if (ip4_addr_ismulticast(dest) && ip4_default_multicast_netif) {
    return ip4_default_multicast_netif;
  }
#endif /* LWIP_MULTICAST_TX_OPTIONS */

  /* bug #54569: in case LWIP_SINGLE_NETIF=1 and LWIP_DEBUGF() disabled, the following loop is optimized away */
  LWIP_UNUSED_ARG(dest);

  /*遍历网卡列表netif_list */
  NETIF_FOREACH(netif) {
    /* 如果网卡已经挂载并且IP地址是有效的 */
    if (netif_is_up(netif) && netif_is_link_up(netif) && !ip4_addr_isany_val(*netif_ip4_addr(netif))) {
      /* 网络掩码匹配? */
      if (ip4_addr_netcmp(dest, netif_ip4_addr(netif), netif_ip4_netmask(netif))) {
        /* 返回找到的网卡netif */
        return netif;
      }
      /* 网关在非广播接口上匹配？ （即在点对点接口中对等） */
      if (((netif->flags & NETIF_FLAG_BROADCAST) == 0) && ip4_addr_cmp(dest, netif_ip4_gw(netif))) {
        /* 返回找到的网卡netif */
        return netif;
      }
    }
  }

#if LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF    /**如果打开环回地址的宏定义 */
  /* loopif is disabled, looopback traffic is passed through any netif */
  if (ip4_addr_isloopback(dest)) {
    /*不检查环回流量的链接*/ 
    if (netif_default != NULL && netif_is_up(netif_default)) {
      return netif_default;
    }
    /*默认netif没有启动，只需使用任何netif进行环回流量*/ 
    NETIF_FOREACH(netif) {
      if (netif_is_up(netif)) {
        return netif;
      }
    }
    return NULL;
  }
#endif /* LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF */

#ifdef LWIP_HOOK_IP4_ROUTE_SRC
  netif = LWIP_HOOK_IP4_ROUTE_SRC(NULL, dest);
  if (netif != NULL) {
    return netif;
  }
#elif defined(LWIP_HOOK_IP4_ROUTE)
  netif = LWIP_HOOK_IP4_ROUTE(dest);
  if (netif != NULL) {
    return netif;
  }
#endif
#endif /* !LWIP_SINGLE_NETIF */

  if ((netif_default == NULL) || !netif_is_up(netif_default) || !netif_is_link_up(netif_default) ||
      ip4_addr_isany_val(*netif_ip4_addr(netif_default)) || ip4_addr_isloopback(dest)) {
    /*找不到匹配的netif，默认的netif不可用。建议使用LWIP_HOOK_IP4_ROUTE（）*/ 
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_route: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    MIB2_STATS_INC(mib2.ipoutnoroutes);
    return NULL;
  }

  return netif_default;
}

#if IP_FORWARD      //启用跨网络转发IP数据包的功能
/**
 * Determine whether an IP address is in a reserved set of addresses
 * that may not be forwarded, or whether datagrams to that destination
 * may be forwarded.
 * @param p the packet to forward
 * @return 1: can forward 0: discard
 */
static int
ip4_canforward(struct pbuf *p)
{
  u32_t addr = lwip_htonl(ip4_addr_get_u32(ip4_current_dest_addr()));

#ifdef LWIP_HOOK_IP4_CANFORWARD
  int ret = LWIP_HOOK_IP4_CANFORWARD(p, addr);
  if (ret >= 0) {
    return ret;
  }
#endif /* LWIP_HOOK_IP4_CANFORWARD */

  if (p->flags & PBUF_FLAG_LLBCAST) {
    /* don't route link-layer broadcasts */
    return 0;
  }
  if ((p->flags & PBUF_FLAG_LLMCAST) || IP_MULTICAST(addr)) {
    /* don't route link-layer multicasts (use LWIP_HOOK_IP4_CANFORWARD instead) */
    return 0;
  }
  if (IP_EXPERIMENTAL(addr)) {
    return 0;
  }
  if (IP_CLASSA(addr)) {
    u32_t net = addr & IP_CLASSA_NET;
    if ((net == 0) || (net == ((u32_t)IP_LOOPBACKNET << IP_CLASSA_NSHIFT))) {
      /* don't route loopback packets */
      return 0;
    }
  }
  return 1;
}

/**
 * Forwards an IP packet. It finds an appropriate route for the
 * packet, decrements the TTL value of the packet, adjusts the
 * checksum and outputs the packet on the appropriate interface.
 *
 * @param p the packet to forward (p->payload points to IP header)
 * @param iphdr the IP header of the input packet
 * @param inp the netif on which this packet was received
 */
static void
ip4_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp)
{
  struct netif *netif;

  PERF_START;
  LWIP_UNUSED_ARG(inp);

  if (!ip4_canforward(p)) {
    goto return_noroute;
  }

  /* RFC3927 2.7: do not forward link-local addresses */
  if (ip4_addr_islinklocal(ip4_current_dest_addr())) {
    LWIP_DEBUGF(IP_DEBUG, ("ip4_forward: not forwarding LLA %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                           ip4_addr1_16(ip4_current_dest_addr()), ip4_addr2_16(ip4_current_dest_addr()),
                           ip4_addr3_16(ip4_current_dest_addr()), ip4_addr4_16(ip4_current_dest_addr())));
    goto return_noroute;
  }

  /* Find network interface where to forward this IP packet to. */
  netif = ip4_route_src(ip4_current_src_addr(), ip4_current_dest_addr());
  if (netif == NULL) {
    LWIP_DEBUGF(IP_DEBUG, ("ip4_forward: no forwarding route for %"U16_F".%"U16_F".%"U16_F".%"U16_F" found\n",
                           ip4_addr1_16(ip4_current_dest_addr()), ip4_addr2_16(ip4_current_dest_addr()),
                           ip4_addr3_16(ip4_current_dest_addr()), ip4_addr4_16(ip4_current_dest_addr())));
    /* @todo: send ICMP_DUR_NET? */
    goto return_noroute;
  }
#if !IP_FORWARD_ALLOW_TX_ON_RX_NETIF
  /* Do not forward packets onto the same network interface on which
   * they arrived. */
  if (netif == inp) {
    LWIP_DEBUGF(IP_DEBUG, ("ip4_forward: not bouncing packets back on incoming interface.\n"));
    goto return_noroute;
  }
#endif /* IP_FORWARD_ALLOW_TX_ON_RX_NETIF */

  /* decrement TTL */
  IPH_TTL_SET(iphdr, IPH_TTL(iphdr) - 1);
  /* send ICMP if TTL == 0 */
  if (IPH_TTL(iphdr) == 0) {
    MIB2_STATS_INC(mib2.ipinhdrerrors);
#if LWIP_ICMP
    /* Don't send ICMP messages in response to ICMP messages */
    if (IPH_PROTO(iphdr) != IP_PROTO_ICMP) {
      icmp_time_exceeded(p, ICMP_TE_TTL);
    }
#endif /* LWIP_ICMP */
    return;
  }

  /* Incrementally update the IP checksum. */
  if (IPH_CHKSUM(iphdr) >= PP_HTONS(0xffffU - 0x100)) {
    IPH_CHKSUM_SET(iphdr, (u16_t)(IPH_CHKSUM(iphdr) + PP_HTONS(0x100) + 1));
  } else {
    IPH_CHKSUM_SET(iphdr, (u16_t)(IPH_CHKSUM(iphdr) + PP_HTONS(0x100)));
  }

  LWIP_DEBUGF(IP_DEBUG, ("ip4_forward: forwarding packet to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                         ip4_addr1_16(ip4_current_dest_addr()), ip4_addr2_16(ip4_current_dest_addr()),
                         ip4_addr3_16(ip4_current_dest_addr()), ip4_addr4_16(ip4_current_dest_addr())));

  IP_STATS_INC(ip.fw);
  MIB2_STATS_INC(mib2.ipforwdatagrams);
  IP_STATS_INC(ip.xmit);

  PERF_STOP("ip4_forward");
  /* don't fragment if interface has mtu set to 0 [loopif] */
  if (netif->mtu && (p->tot_len > netif->mtu)) {
    if ((IPH_OFFSET(iphdr) & PP_NTOHS(IP_DF)) == 0) {
#if IP_FRAG
      ip4_frag(p, netif, ip4_current_dest_addr());
#else /* IP_FRAG */
      /* @todo: send ICMP Destination Unreachable code 13 "Communication administratively prohibited"? */
#endif /* IP_FRAG */
    } else {
#if LWIP_ICMP
      /* send ICMP Destination Unreachable code 4: "Fragmentation Needed and DF Set" */
      icmp_dest_unreach(p, ICMP_DUR_FRAG);
#endif /* LWIP_ICMP */
    }
    return;
  }
  /* transmit pbuf on chosen interface */
  netif->output(netif, p, ip4_current_dest_addr());
  return;
return_noroute:
  MIB2_STATS_INC(mib2.ipoutnoroutes);
}
#endif /* IP_FORWARD */

/** 如果在此netif上接受当前输入数据包，则返回true */
static int
ip4_input_accept(struct netif *netif)
{
  LWIP_DEBUGF(IP_DEBUG, ("ip_input: iphdr->dest 0x%"X32_F" netif->ip_addr 0x%"X32_F" (0x%"X32_F", 0x%"X32_F", 0x%"X32_F")\n",
                         ip4_addr_get_u32(ip4_current_dest_addr()), ip4_addr_get_u32(netif_ip4_addr(netif)),
                         ip4_addr_get_u32(ip4_current_dest_addr()) & ip4_addr_get_u32(netif_ip4_netmask(netif)),
                         ip4_addr_get_u32(netif_ip4_addr(netif)) & ip4_addr_get_u32(netif_ip4_netmask(netif)),
                         ip4_addr_get_u32(ip4_current_dest_addr()) & ~ip4_addr_get_u32(netif_ip4_netmask(netif))));

  /* 网卡已经挂载并且配置？ */
  if ((netif_is_up(netif)) && (!ip4_addr_isany_val(*netif_ip4_addr(netif)))) {
    /* 单播到这个接口地址？ */
    if (ip4_addr_cmp(ip4_current_dest_addr(), netif_ip4_addr(netif)) ||
        /* 或在此接口网络地址上广播？ */
        ip4_addr_isbroadcast(ip4_current_dest_addr(), netif)
#if LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF
        || (ip4_addr_get_u32(ip4_current_dest_addr()) == PP_HTONL(IPADDR_LOOPBACK))
#endif /* LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF */
       ) {
      LWIP_DEBUGF(IP_DEBUG, ("ip4_input: packet accepted on interface %c%c\n",
                             netif->name[0], netif->name[1]));
      /* 接受这个netif  */
      return 1;
    }
#if LWIP_AUTOIP
    /*链接本地地址的连接必须在更改后保留
            netif的地址（RFC3927 ch.1.9）*/
    if (autoip_accept_packet(netif, ip4_current_dest_addr())) {
      LWIP_DEBUGF(IP_DEBUG, ("ip4_input: LLA packet accepted on interface %c%c\n",
                             netif->name[0], netif->name[1]));
      /* accept on this netif */
      return 1;
    }
#endif /* LWIP_AUTOIP */
  }
  return 0;
}


/**
 * 当收到IP数据包的时候这个函数由网络接口​​设备驱动程序调用
 * 该功能对IP报头进行基本检查，例如数据包大小至少大于报头大小等
 * 如果数据包不是发给我们的，则转发数据包（使用ip_forward），始终检查IP校验和。
 *
 * 最后，数据包被递交到到上层协议。
 *
 * @param p 收到的IP数据包（p->有效负载指向IP头）
 * @param inp 收到此数据包的网卡netif
 * @return ERR_OK 如果数据包被处理（如果没有正确被处理则可以返回ERR_ *，但目前始终返回ERR_OK
 */ 
err_t
ip4_input(struct pbuf *p, struct netif *inp)
{
  const struct ip_hdr *iphdr;
  struct netif *netif;
  u16_t iphdr_hlen;
  u16_t iphdr_len;
#if IP_ACCEPT_LINK_LAYER_ADDRESSING || LWIP_IGMP
  int check_ip_src = 1;
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING || LWIP_IGMP */
#if LWIP_RAW
  raw_input_state_t raw_status;
#endif /* LWIP_RAW */

  LWIP_ASSERT_CORE_LOCKED();

  IP_STATS_INC(ip.recv);
  MIB2_STATS_INC(mib2.ipinreceives);

  /* 识别IP数据报首部 */
  iphdr = (struct ip_hdr *)p->payload;
  if (IPH_V(iphdr) != 4) {
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_WARNING, ("IP packet dropped due to bad version number %"U16_F"\n", (u16_t)IPH_V(iphdr)));
    ip4_debug_print(p);
    pbuf_free(p);
    IP_STATS_INC(ip.err);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipinhdrerrors);
    return ERR_OK;
  }

#ifdef LWIP_HOOK_IP4_INPUT
  if (LWIP_HOOK_IP4_INPUT(p, inp)) {
    /* the packet has been eaten */
    return ERR_OK;
  }
#endif

  /* 以字节为单位获取IP头长度 */
  iphdr_hlen = IPH_HL_BYTES(iphdr);
  /* 以字节为单位获取数据报总长度 */
  iphdr_len = lwip_ntohs(IPH_LEN(iphdr));

  /* 修剪pbuf。 对于<60字节的数据包尤其如此 */
  if (iphdr_len < p->tot_len) {
    pbuf_realloc(p, iphdr_len);
  }

  /* 标头长度超过第一个pbuf长度，或者ip长度超过总pbuf长度？ */
  if ((iphdr_hlen > p->len) || (iphdr_len > p->tot_len) || (iphdr_hlen < IP_HLEN)) {
    if (iphdr_hlen < IP_HLEN) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("ip4_input: short IP header (%"U16_F" bytes) received, IP packet dropped\n", iphdr_hlen));
    }
    if (iphdr_hlen > p->len) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("IP header (len %"U16_F") does not fit in first pbuf (len %"U16_F"), IP packet dropped.\n",
                   iphdr_hlen, p->len));
    }
    if (iphdr_len > p->tot_len) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("IP (len %"U16_F") is longer than pbuf (len %"U16_F"), IP packet dropped.\n",
                   iphdr_len, p->tot_len));
    }
    /* 释放数据包 */
    pbuf_free(p);
    IP_STATS_INC(ip.lenerr);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipindiscards);
    return ERR_OK;
  }

  /* 验证校验和 */
#if CHECKSUM_CHECK_IP
  IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_IP) {
    if (inet_chksum(iphdr, iphdr_hlen) != 0) {

      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("Checksum (0x%"X16_F") failed, IP packet dropped.\n", inet_chksum(iphdr, iphdr_hlen)));
      ip4_debug_print(p);
      pbuf_free(p);
      IP_STATS_INC(ip.chkerr);
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinhdrerrors);
      return ERR_OK;
    }
  }
#endif

  /* 将源IP地址与目标IP地址复制到对齐的ip_data*/
  ip_addr_copy_from_ip4(ip_data.current_iphdr_dest, iphdr->dest);
  ip_addr_copy_from_ip4(ip_data.current_iphdr_src, iphdr->src);

  /* 匹配网卡的数据包，即查看一下这个包是不是发给我们的 */
  if (ip4_addr_ismulticast(ip4_current_dest_addr())) {
#if LWIP_IGMP
    if ((inp->flags & NETIF_FLAG_IGMP) && (igmp_lookfor_group(inp, ip4_current_dest_addr()))) {
      /* IGMP Snooping交换机需要0.0.0.0作为源地址（RFC 4541） */
      ip4_addr_t allsystems;
      IP4_ADDR(&allsystems, 224, 0, 0, 1);
      if (ip4_addr_cmp(ip4_current_dest_addr(), &allsystems) &&
          ip4_addr_isany(ip4_current_src_addr())) {
        check_ip_src = 0;
      }
      netif = inp;
    } else {
      netif = NULL;
    }
#else /* LWIP_IGMP */
    if ((netif_is_up(inp)) && (!ip4_addr_isany_val(*netif_ip4_addr(inp)))) {
      netif = inp;
    } else {
      netif = NULL;
    }
#endif /* LWIP_IGMP */
  } else {
    /* 开始尝试使用inp。 如果这是不可接受的，请开始遍历已配置的netifs列表。 */
    if (ip4_input_accept(inp)) {
      netif = inp;
    } else {
      netif = NULL;
#if !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF
      /* 检查一下目标IP地址是否是环回地址 */
      if (!ip4_addr_isloopback(ip4_current_dest_addr()))
#endif /* !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF */
      {
#if !LWIP_SINGLE_NETIF
        NETIF_FOREACH(netif) {
          if (netif == inp) {
            /* we checked that before already */
            continue;
          }
          if (ip4_input_accept(netif)) {
            break;
          }
        }
#endif /* !LWIP_SINGLE_NETIF */
      }
    }
  }

#if IP_ACCEPT_LINK_LAYER_ADDRESSING
  /* 使用链路层寻址（如以太网MAC）*/
  if (netif == NULL) {
    /* 远程端口是DHCP服务器？ */ 
    if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
      const struct udp_hdr *udphdr = (const struct udp_hdr *)((const u8_t *)iphdr + iphdr_hlen);
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: UDP packet to DHCP client port %"U16_F"\n",
                                              lwip_ntohs(udphdr->dest)));
      if (IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(udphdr->dest)) {
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: DHCP packet accepted.\n"));
        netif = inp;
        check_ip_src = 0;
      }
    }
  }
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */

  /* 是广播或组播数据包？  */
#if LWIP_IGMP || IP_ACCEPT_LINK_LAYER_ADDRESSING
  if (check_ip_src
#if IP_ACCEPT_LINK_LAYER_ADDRESSING
      /* DHCP服务器需要0.0.0.0作为源地址（参考RFC 1.1.2.2：3.2.1.3/a） */
      && !ip4_addr_isany_val(*ip4_current_src_addr())
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */
     )
#endif /* LWIP_IGMP || IP_ACCEPT_LINK_LAYER_ADDRESSING */
  {
    if ((ip4_addr_isbroadcast(ip4_current_src_addr(), inp)) ||
        (ip4_addr_ismulticast(ip4_current_src_addr()))) {
      /* 数据包源无效 */
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("ip4_input: packet source is not valid.\n"));
      /* 丢弃数据包 */
      pbuf_free(p);
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinaddrerrors);
      MIB2_STATS_INC(mib2.ipindiscards);
      return ERR_OK;
    }
  }

  /* 如果不是给我们的数据包 */
  if (netif == NULL) {
    /* 路由转发出去或者丢掉数据包 */
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: packet not for us.\n"));
#if IP_FORWARD
    /* 非广播包 */
    if (!ip4_addr_isbroadcast(ip4_current_dest_addr(), inp)) {
      /* 尝试在（其他）网络接口上转发IP数据包 */
      ip4_forward(p, (struct ip_hdr *)p->payload, inp);
    } else
#endif /* IP_FORWARD */
    {
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinaddrerrors);
      MIB2_STATS_INC(mib2.ipindiscards);
    }
    pbuf_free(p);
    return ERR_OK;
  }
  /* 数据包由多个分组（分片）组成？ */
  if ((IPH_OFFSET(iphdr) & PP_HTONS(IP_OFFMASK | IP_MF)) != 0) {
#if IP_REASSEMBLY /* packet fragment reassembly code present? */
    LWIP_DEBUGF(IP_DEBUG, ("IP packet is a fragment (id=0x%04"X16_F" tot_len=%"U16_F" len=%"U16_F" MF=%"U16_F" offset=%"U16_F"), calling ip4_reass()\n",
                           lwip_ntohs(IPH_ID(iphdr)), p->tot_len, lwip_ntohs(IPH_LEN(iphdr)), (u16_t)!!(IPH_OFFSET(iphdr) & PP_HTONS(IP_MF)), (u16_t)((lwip_ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK) * 8)));
    /* reassemble the packet*/
    p = ip4_reass(p);
    /* 数据包没有完全重组？*/
    if (p == NULL) {
      return ERR_OK;
    }
    iphdr = (const struct ip_hdr *)p->payload;
#else /* IP_REASSEMBLY == 0, no packet fragment reassembly code present */
    pbuf_free(p);
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("IP packet dropped since it was fragmented (0x%"X16_F") (while IP_REASSEMBLY == 0).\n",
                lwip_ntohs(IPH_OFFSET(iphdr))));
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* 不支持的协议功能 */
    MIB2_STATS_INC(mib2.ipinunknownprotos);
    return ERR_OK;
#endif /* IP_REASSEMBLY */
  }

#if IP_OPTIONS_ALLOWED == 0 /* no support for IP options in the IP header? */

#if LWIP_IGMP
  /* there is an extra "router alert" option in IGMP messages which we allow for but do not police */
  if ((iphdr_hlen > IP_HLEN) &&  (IPH_PROTO(iphdr) != IP_PROTO_IGMP)) {
#else
  if (iphdr_hlen > IP_HLEN) {
#endif /* LWIP_IGMP */
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("IP packet dropped since there were IP options (while IP_OPTIONS_ALLOWED == 0).\n"));
    pbuf_free(p);
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* unsupported protocol feature */
    MIB2_STATS_INC(mib2.ipinunknownprotos);
    return ERR_OK;
  }
#endif /* IP_OPTIONS_ALLOWED == 0 */

  /* 递交到上层协议 */
  LWIP_DEBUGF(IP_DEBUG, ("ip4_input: \n"));
  ip4_debug_print(p);
  LWIP_DEBUGF(IP_DEBUG, ("ip4_input: p->len %"U16_F" p->tot_len %"U16_F"\n", p->len, p->tot_len));

  ip_data.current_netif = netif;
  ip_data.current_input_netif = inp;
  ip_data.current_ip4_header = iphdr;
  ip_data.current_ip_header_tot_len = IPH_HL_BYTES(iphdr);

#if LWIP_RAW
  /* 原始输入层没有获取这个数据包，则通过数据包中的协议递交到上层 */
  raw_status = raw_input(p, inp);
  if (raw_status != RAW_INPUT_EATEN)
#endif /* LWIP_RAW */
  {
    pbuf_remove_header(p, iphdr_hlen); /* 移动pbuf的指针，指向数据区域指针(相当于提取上层协议的报文) */

    switch (IPH_PROTO(iphdr)) {
#if LWIP_UDP
      case IP_PROTO_UDP:    /** 如果上层协议是UDP协议，则通过udp_input()递交到上层 */
#if LWIP_UDPLITE
      case IP_PROTO_UDPLITE:
#endif /* LWIP_UDPLITE */
        MIB2_STATS_INC(mib2.ipindelivers);
        udp_input(p, inp);
        break;
#endif /* LWIP_UDP */
#if LWIP_TCP
      case IP_PROTO_TCP:       /** 如果上层协议是TCP协议，则通过tcp_input()递交到上层 */
        MIB2_STATS_INC(mib2.ipindelivers);
        tcp_input(p, inp);
        break;
#endif /* LWIP_TCP */
#if LWIP_ICMP
      case IP_PROTO_ICMP:      /** 如果上层协议是ICMP协议，则通过icmp_input()递交到上层 */
        MIB2_STATS_INC(mib2.ipindelivers);
        icmp_input(p, inp);
        break;
#endif /* LWIP_ICMP */
#if LWIP_IGMP
      case IP_PROTO_IGMP:     /** 如果上层协议是IGMP协议，则通过igmp_input()递交到上层 */
        igmp_input(p, inp, ip4_current_dest_addr());
        break;
#endif /* LWIP_IGMP */
      default:
#if LWIP_RAW        
        if (raw_status == RAW_INPUT_DELIVERED) {
          MIB2_STATS_INC(mib2.ipindelivers);
        } else
#endif /* LWIP_RAW */
        {
#if LWIP_ICMP
          /* 如果没有对应的上层协议（非广播包），则返回一个ICMP包，目标协议不可搭 */
          if (!ip4_addr_isbroadcast(ip4_current_dest_addr(), netif) &&
              !ip4_addr_ismulticast(ip4_current_dest_addr())) {
            pbuf_header_force(p, (s16_t)iphdr_hlen); /* 获取ip数据报首部，无需检查 */
            icmp_dest_unreach(p, ICMP_DUR_PROTO);
          }
#endif /* LWIP_ICMP */

          LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("Unsupported transport protocol %"U16_F"\n", (u16_t)IPH_PROTO(iphdr)));

          IP_STATS_INC(ip.proterr);
          IP_STATS_INC(ip.drop);
          MIB2_STATS_INC(mib2.ipinunknownprotos);
        }
        pbuf_free(p);
        break;
    }
  }

  /* @todo：这不是必要的......  */
  ip_data.current_netif = NULL;
  ip_data.current_input_netif = NULL;
  ip_data.current_ip4_header = NULL;
  ip_data.current_ip_header_tot_len = 0;
  ip4_addr_set_any(ip4_current_src_addr());
  ip4_addr_set_any(ip4_current_dest_addr());

  return ERR_OK;
}

/**
 * 在网络接口上发送IP数据包。这个函数构造IP数据包首部并计算IP头校验和，
 * 如果源IP地址为NULL，在发送的时候就填写发送网卡的IP地址为源IP地址
 * 如果目标IP地址是LWIP_IP_HDRINCL，则假定pbuf已经存在包括IP头和有效负载指向它而不是数据。
 * 
 * @param p 要发送的数据包（p->payload（有效负载）指向数据，如果dest == LWIP_IP_HDRINCL，则p已包含IP头和p->有效负载指向该IP头）
 * @param src 要发送的源IP地址（如果src == IP4_ADDR_ANY，则用发送的netif绑定的IP地址用作源地址）
 * @param dest 目的IP地址
 * @param ttl 要在IP标头中设置的TTL值(生存时间)
 * @param tos 用于在IP标头中设置的TOS值
 * @param proto 将在IP头中设置对应的上层协议
 * @param netif 发送此数据包的netif
 * @return ERR_OK 如果数据包发送正常就返回ok，
 *         如果p没有足够的空间用于IP /LINK标头，则为ERR_BUF
 *         其他则返回netif->output返回的错误
 *
 * @note ip_id：RFC791“某些主机可能只需使用
 * 独立于目的地的唯一标识符“
 */ 
err_t
ip4_output_if(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
              u8_t ttl, u8_t tos,
              u8_t proto, struct netif *netif)
{
#if IP_OPTIONS_SEND
  return ip4_output_if_opt(p, src, dest, ttl, tos, proto, netif, NULL, 0);
}


/**
 * 与ip_output_if（）相同，但可以包含IP选项：
 *
 * @param ip_options指向IP选项的指针，复制到IP头中
 * @param optlen ip_options的长度
 */ 
err_t
ip4_output_if_opt(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
                  u8_t ttl, u8_t tos, u8_t proto, struct netif *netif, void *ip_options,
                  u16_t optlen)
{
#endif /* IP_OPTIONS_SEND */
  const ip4_addr_t *src_used = src;
  if (dest != LWIP_IP_HDRINCL) {
    if (ip4_addr_isany(src)) {
      src_used = netif_ip4_addr(netif);
    }
  }

#if IP_OPTIONS_SEND
  return ip4_output_if_opt_src(p, src_used, dest, ttl, tos, proto, netif,
                               ip_options, optlen);
#else /* IP_OPTIONS_SEND */
  return ip4_output_if_src(p, src_used, dest, ttl, tos, proto, netif);
#endif /* IP_OPTIONS_SEND */
}


/**
 * 与ip_output_if()相同，当源地址是'IP4_ADDR_ANY'时，'src'地址不会被netif地址替换
 */ 
err_t
ip4_output_if_src(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
                  u8_t ttl, u8_t tos,
                  u8_t proto, struct netif *netif)
{
#if IP_OPTIONS_SEND
  return ip4_output_if_opt_src(p, src, dest, ttl, tos, proto, netif, NULL, 0);
}

/**
 * 与ip4_output_if_opt()相同，当源地址是'IP4_ADDR_ANY'时，'src'地址不会被netif地址替换
 */ 
err_t
ip4_output_if_opt_src(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
                      u8_t ttl, u8_t tos, u8_t proto, struct netif *netif, void *ip_options,
                      u16_t optlen)
{
#endif /* IP_OPTIONS_SEND */
  struct ip_hdr *iphdr;
  ip4_addr_t dest_addr;
#if CHECKSUM_GEN_IP_INLINE
  u32_t chk_sum = 0;
#endif /* CHECKSUM_GEN_IP_INLINE */

  LWIP_ASSERT_CORE_LOCKED();
  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  MIB2_STATS_INC(mib2.ipoutrequests);

  /* 应该要构建IP首部还是已经包含在pbuf中了？如果是要构建IP数据报首部 */
  if (dest != LWIP_IP_HDRINCL) {
    u16_t ip_hlen = IP_HLEN;
#if IP_OPTIONS_SEND
    u16_t optlen_aligned = 0;
    if (optlen != 0) {
#if CHECKSUM_GEN_IP_INLINE
      int i;
#endif /* CHECKSUM_GEN_IP_INLINE */
      if (optlen > (IP_HLEN_MAX - IP_HLEN)) {
        /* 选项字段太长 */
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output_if_opt: optlen too long\n"));
        IP_STATS_INC(ip.err);
        MIB2_STATS_INC(mib2.ipoutdiscards);
        return ERR_VAL;
      }
      /* 选项字段按照4字节对齐 */
      optlen_aligned = (u16_t)((optlen + 3) & ~3);
      ip_hlen = (u16_t)(ip_hlen + optlen_aligned);
      /* 首先写入IP选项字段 */
      if (pbuf_add_header(p, optlen_aligned)) {
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output_if_opt: not enough room for IP options in pbuf\n"));
        IP_STATS_INC(ip.err);
        MIB2_STATS_INC(mib2.ipoutdiscards);
        return ERR_BUF;
      }
      MEMCPY(p->payload, ip_options, optlen);
      if (optlen < optlen_aligned) {
        /* 剩余字节清零 */
        memset(((char *)p->payload) + optlen, 0, (size_t)(optlen_aligned - optlen));
      }
#if CHECKSUM_GEN_IP_INLINE
      for (i = 0; i < optlen_aligned / 2; i++) {
        chk_sum += ((u16_t *)p->payload)[i];
      }
#endif /* CHECKSUM_GEN_IP_INLINE */
    }
#endif /* IP_OPTIONS_SEND */
    /* 生成IP头 */
    if (pbuf_add_header(p, IP_HLEN)) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output: not enough room for IP header in pbuf\n"));

      IP_STATS_INC(ip.err);
      MIB2_STATS_INC(mib2.ipoutdiscards);
      return ERR_BUF;
    }

    iphdr = (struct ip_hdr *)p->payload;
    LWIP_ASSERT("check that first pbuf can hold struct ip_hdr",
                (p->len >= sizeof(struct ip_hdr)));

    IPH_TTL_SET(iphdr, ttl);
    IPH_PROTO_SET(iphdr, proto);
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += PP_NTOHS(proto | (ttl << 8));
#endif /* CHECKSUM_GEN_IP_INLINE */

    /* 构建目的IP地址，此处的目的IP地址不能为NULL */
    ip4_addr_copy(iphdr->dest, *dest);  
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += ip4_addr_get_u32(&iphdr->dest) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->dest) >> 16;
#endif /* CHECKSUM_GEN_IP_INLINE */

    IPH_VHL_SET(iphdr, 4, ip_hlen / 4);
    IPH_TOS_SET(iphdr, tos);
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += PP_NTOHS(tos | (iphdr->_v_hl << 8));
#endif /* CHECKSUM_GEN_IP_INLINE */
    IPH_LEN_SET(iphdr, lwip_htons(p->tot_len));
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += iphdr->_len;
#endif /* CHECKSUM_GEN_IP_INLINE */
    IPH_OFFSET_SET(iphdr, 0);
    IPH_ID_SET(iphdr, lwip_htons(ip_id));
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += iphdr->_id;
#endif /* CHECKSUM_GEN_IP_INLINE */
    ++ip_id;

    if (src == NULL) {
      ip4_addr_copy(iphdr->src, *IP4_ADDR_ANY4);    /** 构建源IP地址 */
    } else {
      /* 此处的源IP地址不能为NULL */
      ip4_addr_copy(iphdr->src, *src);
    }

#if CHECKSUM_GEN_IP_INLINE
    chk_sum += ip4_addr_get_u32(&iphdr->src) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->src) >> 16;
    chk_sum = (chk_sum >> 16) + (chk_sum & 0xFFFF);
    chk_sum = (chk_sum >> 16) + chk_sum;
    chk_sum = ~chk_sum;
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
      iphdr->_chksum = (u16_t)chk_sum; /* network order */
    }
#if LWIP_CHECKSUM_CTRL_PER_NETIF
    else {
      IPH_CHKSUM_SET(iphdr, 0);
    }
#endif /* LWIP_CHECKSUM_CTRL_PER_NETIF*/
#else /* CHECKSUM_GEN_IP_INLINE */
    IPH_CHKSUM_SET(iphdr, 0);
#if CHECKSUM_GEN_IP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
      IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, ip_hlen));
    }
#endif /* CHECKSUM_GEN_IP */
#endif /* CHECKSUM_GEN_IP_INLINE */
  } else {
    /* IP头已包含在pbuf中 */
    if (p->len < IP_HLEN) {   
      /** pbuf的长度小于IP数据报首部长度(20字节) */
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output: LWIP_IP_HDRINCL but pbuf is too short\n"));
      IP_STATS_INC(ip.err);
      MIB2_STATS_INC(mib2.ipoutdiscards);
      return ERR_BUF;
    }
    iphdr = (struct ip_hdr *)p->payload;    /** 直接从数据区域获取IP数据报首部 */
    ip4_addr_copy(dest_addr, iphdr->dest);  /** 获取目的IP地址 */
    dest = &dest_addr;
  }

  IP_STATS_INC(ip.xmit);

  LWIP_DEBUGF(IP_DEBUG, ("ip4_output_if: %c%c%"U16_F"\n", netif->name[0], netif->name[1], (u16_t)netif->num));
  ip4_debug_print(p);

#if ENABLE_LOOPBACK   /** 换回接口 */
  if (ip4_addr_cmp(dest, netif_ip4_addr(netif))
#if !LWIP_HAVE_LOOPIF
      || ip4_addr_isloopback(dest)
#endif /* !LWIP_HAVE_LOOPIF */
     ) {
    /* 数据包是给自己的，将其放入环回接口 */
    LWIP_DEBUGF(IP_DEBUG, ("netif_loop_output()"));
    return netif_loop_output(netif, p);
  }
#if LWIP_MULTICAST_TX_OPTIONS
  if ((p->flags & PBUF_FLAG_MCASTLOOP) != 0) {
    netif_loop_output(netif, p);
  }
#endif /* LWIP_MULTICAST_TX_OPTIONS */
#endif /* ENABLE_LOOPBACK */
#if IP_FRAG
  /** 要发送的数据报大于mtu，需要分片，此处的前提是使能了IP_FRAG (IP分片) */
  if (netif->mtu && (p->tot_len > netif->mtu)) {
    return ip4_frag(p, netif, dest);  /** 调用IP数据报分片函数将数据报分片发送出去 */
  }
#endif /* IP_FRAG */

  LWIP_DEBUGF(IP_DEBUG, ("ip4_output_if: call netif->output()\n"));
  return netif->output(netif, p, dest);   /** 如果不需要分片就直接通过网卡发送出去，netif->output() */
}


/**
 * ip_output_if的简化版接口。它找到发送数据包的netif网络接口并调用ip_output_if来完成实际工作。
 *
 * @param p 要发送的数据包（p->payload（有效负载）指向数据，如果dest == LWIP_IP_HDRINCL，则p已包含IP头和p->有效负载指向该IP头）
 * @param src 要发送的源IP地址（如果src == IP4_ADDR_ANY，则用发送的netif绑定的IP地址用作源地址）
 * @param dest 目的IP地址
 * @param ttl 要在IP标头中设置的TTL值(生存时间)
 * @param tos 用于在IP标头中设置的TOS值
 * @param proto 将在IP头中设置对应的上层协议
 * @return ERR_OK 如果数据包发送正常就返回ok，
 *         如果p没有足够的空间用于IP /LINK标头，则为ERR_BUF
 *         其他则返回netif->output返回的错误
 * @return ERR_RTE如果没有找到路线
 * 请参阅ip_output_if（）以获取更多返回值
 */ 
err_t
ip4_output(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
           u8_t ttl, u8_t tos, u8_t proto)
{
  struct netif *netif;

  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  if ((netif = ip4_route_src(src, dest)) == NULL) {
    LWIP_DEBUGF(IP_DEBUG, ("ip4_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                           ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    return ERR_RTE;
  }

  return ip4_output_if(p, src, dest, ttl, tos, proto, netif);
}

#if LWIP_NETIF_USE_HINTS
/** 与ip_output类似 */
/** Like ip_output, but takes and addr_hint pointer that is passed on to netif->addr_hint
 *  before calling ip_output_if.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif_hint netif output hint pointer set to netif->hint before
 *        calling ip_output_if()
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
err_t
ip4_output_hinted(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
                  u8_t ttl, u8_t tos, u8_t proto, struct netif_hint *netif_hint)
{
  struct netif *netif;
  err_t err;

  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  if ((netif = ip4_route_src(src, dest)) == NULL) {
    LWIP_DEBUGF(IP_DEBUG, ("ip4_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                           ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    return ERR_RTE;
  }

  NETIF_SET_HINTS(netif, netif_hint);
  err = ip4_output_if(p, src, dest, ttl, tos, proto, netif);
  NETIF_RESET_HINTS(netif);

  return err;
}
#endif /* LWIP_NETIF_USE_HINTS*/

#if IP_DEBUG
/* Print an IP header by using LWIP_DEBUGF
 * @param p an IP packet, p->payload pointing to the IP header
 */
void
ip4_debug_print(struct pbuf *p)
{
  struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

  LWIP_DEBUGF(IP_DEBUG, ("IP header:\n"));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|%2"S16_F" |%2"S16_F" |  0x%02"X16_F" |     %5"U16_F"     | (v, hl, tos, len)\n",
                         (u16_t)IPH_V(iphdr),
                         (u16_t)IPH_HL(iphdr),
                         (u16_t)IPH_TOS(iphdr),
                         lwip_ntohs(IPH_LEN(iphdr))));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|    %5"U16_F"      |%"U16_F"%"U16_F"%"U16_F"|    %4"U16_F"   | (id, flags, offset)\n",
                         lwip_ntohs(IPH_ID(iphdr)),
                         (u16_t)(lwip_ntohs(IPH_OFFSET(iphdr)) >> 15 & 1),
                         (u16_t)(lwip_ntohs(IPH_OFFSET(iphdr)) >> 14 & 1),
                         (u16_t)(lwip_ntohs(IPH_OFFSET(iphdr)) >> 13 & 1),
                         (u16_t)(lwip_ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK)));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |    0x%04"X16_F"     | (ttl, proto, chksum)\n",
                         (u16_t)IPH_TTL(iphdr),
                         (u16_t)IPH_PROTO(iphdr),
                         lwip_ntohs(IPH_CHKSUM(iphdr))));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  | (src)\n",
                         ip4_addr1_16_val(iphdr->src),
                         ip4_addr2_16_val(iphdr->src),
                         ip4_addr3_16_val(iphdr->src),
                         ip4_addr4_16_val(iphdr->src)));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  | (dest)\n",
                         ip4_addr1_16_val(iphdr->dest),
                         ip4_addr2_16_val(iphdr->dest),
                         ip4_addr3_16_val(iphdr->dest),
                         ip4_addr4_16_val(iphdr->dest)));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
}
#endif /* IP_DEBUG */

#endif /* LWIP_IPV4 */
