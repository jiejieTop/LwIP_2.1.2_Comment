# LwIP_2.1.2_Comment
LwIP 2.1.2 版本的源码中文注释

```

## 【目录结构】
lwip-2.1.2
│  CHANGELOG
│  CMakeLists.txt
│  COPYING
│  FEATURES
│  FILES
│  info.txt
│  README
│  UPGRADING
│  
├─doc
│  │  contrib.txt
│  │  FILES
│  │  mdns.txt
│  │  mqtt_client.txt
│  │  NO_SYS_SampleCode.c
│  │  ppp.txt
│  │  savannah.txt
│  │  ZeroCopyRx.c
│  │  
│  └─doxygen
│          generate.bat
│          generate.sh
│          lwip.Doxyfile
│          lwip.Doxyfile.cmake.in
│          main_page.h
│          
├─src
│  │  Filelists.cmake
│  │  Filelists.mk
│  │  FILES
│  │  
│  ├─api
│  │      api_lib.c
│  │      api_msg.c
│  │      err.c
│  │      if_api.c
│  │      netbuf.c
│  │      netdb.c
│  │      netifapi.c
│  │      sockets.c
│  │      tcpip.c
│  │      
│  ├─apps
│  │  ├─altcp_tls
│  │  │      altcp_tls_mbedtls.c
│  │  │      altcp_tls_mbedtls_mem.c
│  │  │      altcp_tls_mbedtls_mem.h
│  │  │      altcp_tls_mbedtls_structs.h
│  │  │      
│  │  ├─http
│  │  │  │  altcp_proxyconnect.c
│  │  │  │  fs.c
│  │  │  │  fsdata.c
│  │  │  │  fsdata.h
│  │  │  │  httpd.c
│  │  │  │  httpd_structs.h
│  │  │  │  http_client.c
│  │  │  │  
│  │  │  ├─fs
│  │  │  │  │  404.html
│  │  │  │  │  index.html
│  │  │  │  │  
│  │  │  │  └─img
│  │  │  │          sics.gif
│  │  │  │          
│  │  │  └─makefsdata
│  │  │          makefsdata
│  │  │          makefsdata.c
│  │  │          readme.txt
│  │  │          tinydir.h
│  │  │          
│  │  ├─lwiperf
│  │  │      lwiperf.c
│  │  │      
│  │  ├─mdns
│  │  │      mdns.c
│  │  │      
│  │  ├─mqtt
│  │  │      mqtt.c
│  │  │      
│  │  ├─netbiosns
│  │  │      netbiosns.c
│  │  │      
│  │  ├─smtp
│  │  │      smtp.c
│  │  │      
│  │  ├─snmp
│  │  │      snmpv3.c
│  │  │      snmpv3_mbedtls.c
│  │  │      snmpv3_priv.h
│  │  │      snmp_asn1.c
│  │  │      snmp_asn1.h
│  │  │      snmp_core.c
│  │  │      snmp_core_priv.h
│  │  │      snmp_mib2.c
│  │  │      snmp_mib2_icmp.c
│  │  │      snmp_mib2_interfaces.c
│  │  │      snmp_mib2_ip.c
│  │  │      snmp_mib2_snmp.c
│  │  │      snmp_mib2_system.c
│  │  │      snmp_mib2_tcp.c
│  │  │      snmp_mib2_udp.c
│  │  │      snmp_msg.c
│  │  │      snmp_msg.h
│  │  │      snmp_netconn.c
│  │  │      snmp_pbuf_stream.c
│  │  │      snmp_pbuf_stream.h
│  │  │      snmp_raw.c
│  │  │      snmp_scalar.c
│  │  │      snmp_snmpv2_framework.c
│  │  │      snmp_snmpv2_usm.c
│  │  │      snmp_table.c
│  │  │      snmp_threadsync.c
│  │  │      snmp_traps.c
│  │  │      
│  │  ├─sntp
│  │  │      sntp.c
│  │  │      
│  │  └─tftp
│  │          tftp_server.c
│  │          
│  ├─core
│  │  │  altcp.c
│  │  │  altcp_alloc.c
│  │  │  altcp_tcp.c
│  │  │  def.c
│  │  │  dns.c
│  │  │  inet_chksum.c
│  │  │  init.c
│  │  │  ip.c
│  │  │  mem.c
│  │  │  memp.c
│  │  │  netif.c
│  │  │  pbuf.c
│  │  │  raw.c
│  │  │  stats.c
│  │  │  sys.c
│  │  │  tcp.c
│  │  │  tcp_in.c
│  │  │  tcp_out.c
│  │  │  timeouts.c
│  │  │  udp.c
│  │  │  
│  │  ├─ipv4
│  │  │      autoip.c
│  │  │      dhcp.c
│  │  │      etharp.c
│  │  │      icmp.c
│  │  │      igmp.c
│  │  │      ip4.c
│  │  │      ip4_addr.c
│  │  │      ip4_frag.c
│  │  │      
│  │  └─ipv6
│  │          dhcp6.c
│  │          ethip6.c
│  │          icmp6.c
│  │          inet6.c
│  │          ip6.c
│  │          ip6_addr.c
│  │          ip6_frag.c
│  │          mld6.c
│  │          nd6.c
│  │          
│  ├─include
│  │  ├─compat
│  │  │  ├─posix
│  │  │  │  │  netdb.h
│  │  │  │  │  
│  │  │  │  ├─arpa
│  │  │  │  │      inet.h
│  │  │  │  │      
│  │  │  │  ├─net
│  │  │  │  │      if.h
│  │  │  │  │      
│  │  │  │  └─sys
│  │  │  │          socket.h
│  │  │  │          
│  │  │  └─stdc
│  │  │          errno.h
│  │  │          
│  │  ├─lwip
│  │  │  │  altcp.h
│  │  │  │  altcp_tcp.h
│  │  │  │  altcp_tls.h
│  │  │  │  api.h
│  │  │  │  arch.h
│  │  │  │  autoip.h
│  │  │  │  debug.h
│  │  │  │  def.h
│  │  │  │  dhcp.h
│  │  │  │  dhcp6.h
│  │  │  │  dns.h
│  │  │  │  err.h
│  │  │  │  errno.h
│  │  │  │  etharp.h
│  │  │  │  ethip6.h
│  │  │  │  icmp.h
│  │  │  │  icmp6.h
│  │  │  │  if_api.h
│  │  │  │  igmp.h
│  │  │  │  inet.h
│  │  │  │  inet_chksum.h
│  │  │  │  init.h
│  │  │  │  init.h.cmake.in
│  │  │  │  ip.h
│  │  │  │  ip4.h
│  │  │  │  ip4_addr.h
│  │  │  │  ip4_frag.h
│  │  │  │  ip6.h
│  │  │  │  ip6_addr.h
│  │  │  │  ip6_frag.h
│  │  │  │  ip6_zone.h
│  │  │  │  ip_addr.h
│  │  │  │  mem.h
│  │  │  │  memp.h
│  │  │  │  mld6.h
│  │  │  │  nd6.h
│  │  │  │  netbuf.h
│  │  │  │  netdb.h
│  │  │  │  netif.h
│  │  │  │  netifapi.h
│  │  │  │  opt.h
│  │  │  │  pbuf.h
│  │  │  │  raw.h
│  │  │  │  sio.h
│  │  │  │  snmp.h
│  │  │  │  sockets.h
│  │  │  │  stats.h
│  │  │  │  sys.h
│  │  │  │  tcp.h
│  │  │  │  tcpbase.h
│  │  │  │  tcpip.h
│  │  │  │  timeouts.h
│  │  │  │  udp.h
│  │  │  │  
│  │  │  ├─apps
│  │  │  │      altcp_proxyconnect.h
│  │  │  │      altcp_tls_mbedtls_opts.h
│  │  │  │      FILES
│  │  │  │      fs.h
│  │  │  │      httpd.h
│  │  │  │      httpd_opts.h
│  │  │  │      http_client.h
│  │  │  │      lwiperf.h
│  │  │  │      mdns.h
│  │  │  │      mdns_opts.h
│  │  │  │      mdns_priv.h
│  │  │  │      mqtt.h
│  │  │  │      mqtt_opts.h
│  │  │  │      mqtt_priv.h
│  │  │  │      netbiosns.h
│  │  │  │      netbiosns_opts.h
│  │  │  │      smtp.h
│  │  │  │      smtp_opts.h
│  │  │  │      snmp.h
│  │  │  │      snmpv3.h
│  │  │  │      snmp_core.h
│  │  │  │      snmp_mib2.h
│  │  │  │      snmp_opts.h
│  │  │  │      snmp_scalar.h
│  │  │  │      snmp_snmpv2_framework.h
│  │  │  │      snmp_snmpv2_usm.h
│  │  │  │      snmp_table.h
│  │  │  │      snmp_threadsync.h
│  │  │  │      sntp.h
│  │  │  │      sntp_opts.h
│  │  │  │      tftp_opts.h
│  │  │  │      tftp_server.h
│  │  │  │      
│  │  │  ├─priv
│  │  │  │      altcp_priv.h
│  │  │  │      api_msg.h
│  │  │  │      memp_priv.h
│  │  │  │      memp_std.h
│  │  │  │      mem_priv.h
│  │  │  │      nd6_priv.h
│  │  │  │      raw_priv.h
│  │  │  │      sockets_priv.h
│  │  │  │      tcpip_priv.h
│  │  │  │      tcp_priv.h
│  │  │  │      
│  │  │  └─prot
│  │  │          autoip.h
│  │  │          dhcp.h
│  │  │          dhcp6.h
│  │  │          dns.h
│  │  │          etharp.h
│  │  │          ethernet.h
│  │  │          iana.h
│  │  │          icmp.h
│  │  │          icmp6.h
│  │  │          ieee.h
│  │  │          igmp.h
│  │  │          ip.h
│  │  │          ip4.h
│  │  │          ip6.h
│  │  │          mld6.h
│  │  │          nd6.h
│  │  │          tcp.h
│  │  │          udp.h
│  │  │          
│  │  └─netif
│  │      │  bridgeif.h
│  │      │  bridgeif_opts.h
│  │      │  etharp.h
│  │      │  ethernet.h
│  │      │  ieee802154.h
│  │      │  lowpan6.h
│  │      │  lowpan6_ble.h
│  │      │  lowpan6_common.h
│  │      │  lowpan6_opts.h
│  │      │  slipif.h
│  │      │  zepif.h
│  │      │  
│  │      └─ppp
│  │          │  ccp.h
│  │          │  chap-md5.h
│  │          │  chap-new.h
│  │          │  chap_ms.h
│  │          │  eap.h
│  │          │  ecp.h
│  │          │  eui64.h
│  │          │  fsm.h
│  │          │  ipcp.h
│  │          │  ipv6cp.h
│  │          │  lcp.h
│  │          │  magic.h
│  │          │  mppe.h
│  │          │  ppp.h
│  │          │  pppapi.h
│  │          │  pppcrypt.h
│  │          │  pppdebug.h
│  │          │  pppoe.h
│  │          │  pppol2tp.h
│  │          │  pppos.h
│  │          │  ppp_impl.h
│  │          │  ppp_opts.h
│  │          │  upap.h
│  │          │  vj.h
│  │          │  
│  │          └─polarssl
│  │                  arc4.h
│  │                  des.h
│  │                  md4.h
│  │                  md5.h
│  │                  sha1.h
│  │                  
│  └─netif
│      │  bridgeif.c
│      │  bridgeif_fdb.c
│      │  ethernet.c
│      │  FILES
│      │  lowpan6.c
│      │  lowpan6_ble.c
│      │  lowpan6_common.c
│      │  slipif.c
│      │  zepif.c
│      │  
│      └─ppp
│          │  auth.c
│          │  ccp.c
│          │  chap-md5.c
│          │  chap-new.c
│          │  chap_ms.c
│          │  demand.c
│          │  eap.c
│          │  ecp.c
│          │  eui64.c
│          │  fsm.c
│          │  ipcp.c
│          │  ipv6cp.c
│          │  lcp.c
│          │  magic.c
│          │  mppe.c
│          │  multilink.c
│          │  ppp.c
│          │  pppapi.c
│          │  pppcrypt.c
│          │  PPPD_FOLLOWUP
│          │  pppoe.c
│          │  pppol2tp.c
│          │  pppos.c
│          │  upap.c
│          │  utils.c
│          │  vj.c
│          │  
│          └─polarssl
│                  arc4.c
│                  des.c
│                  md4.c
│                  md5.c
│                  README
│                  sha1.c
│                  
└─test
    ├─fuzz
    │  │  config.h
    │  │  fuzz.c
    │  │  lwipopts.h
    │  │  Makefile
    │  │  output_to_pcap.sh
    │  │  README
    │  │  
    │  └─inputs
    │      ├─arp
    │      │      arp_req.bin
    │      │      
    │      ├─icmp
    │      │      icmp_ping.bin
    │      │      
    │      ├─ipv6
    │      │      neighbor_solicitation.bin
    │      │      router_adv.bin
    │      │      
    │      ├─tcp
    │      │      tcp_syn.bin
    │      │      
    │      └─udp
    │              udp_port_5000.bin
    │              
    ├─sockets
    │      sockets_stresstest.c
    │      sockets_stresstest.h
    │      
    └─unit
        │  Filelists.cmake
        │  Filelists.mk
        │  lwipopts.h
        │  lwip_check.h
        │  lwip_unittests.c
        │  
        ├─api
        │      test_sockets.c
        │      test_sockets.h
        │      
        ├─arch
        │      sys_arch.c
        │      sys_arch.h
        │      
        ├─core
        │      test_def.c
        │      test_def.h
        │      test_mem.c
        │      test_mem.h
        │      test_netif.c
        │      test_netif.h
        │      test_pbuf.c
        │      test_pbuf.h
        │      test_timers.c
        │      test_timers.h
        │      
        ├─dhcp
        │      test_dhcp.c
        │      test_dhcp.h
        │      
        ├─etharp
        │      test_etharp.c
        │      test_etharp.h
        │      
        ├─ip4
        │      test_ip4.c
        │      test_ip4.h
        │      
        ├─ip6
        │      test_ip6.c
        │      test_ip6.h
        │      
        ├─mdns
        │      test_mdns.c
        │      test_mdns.h
        │      
        ├─mqtt
        │      test_mqtt.c
        │      test_mqtt.h
        │      
        ├─tcp
        │      tcp_helper.c
        │      tcp_helper.h
        │      test_tcp.c
        │      test_tcp.h
        │      test_tcp_oos.c
        │      test_tcp_oos.h
        │      
        └─udp
                test_udp.c
                test_udp.h
                
```