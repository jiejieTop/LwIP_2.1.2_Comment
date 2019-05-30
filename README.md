# LwIP_2.1.2_Comment
LwIP 2.1.2 版本的源码中文注释


## 【目录结构】
lwip-2.1.2
│  CHANGELOG	// 版本更新记录，从中可以看到LwIP不同版本的变化
│  COPYING
│  CMakeLists.txt
│  FEATURES   //特点
│  FILES		// 其中说明了其所在目录下的各目录或文件的用途。在不同的目录下会有不同的该文件
│  README
│  UPGRADING	// 版本升级后可能出现不兼容，该文档记录了从老版本升级需要修改的地方。对于升级自己使用的LwIP版本时很有用处。
├─doc
│  │  contrib.txt	// LwIP作为开源软件，如果想要为其做贡献，则需要遵循一定的准则，例如：提交代码的风格、报告Bug等。该文档给出了详细的贡献准则。
│  │  doxygen_docs.zip	// 用doxygen生成的LwIP的配套文档
│  │  FILES			// 其中说明了该目录下的每个文件的用途
│  │  mdns.txt		// MDNS的说明文档
│  │  mqtt_client.txt
│  │  NO_SYS_SampleCode.c
│  │  ppp.txt		// lwIP的PPP接口文档
│  │  rawapi.txt	// 告诉读者怎样使用协议栈的Raw/Callback API进行编程
│  │  savannah.txt	// 说明了如何获取当前的开发源代码
│  │  sys_arch.txt  // 在有操作系统的移植的时候会被使用到，包含了移植说明，规定了移植者需要实现的函数、宏定义等，后面有详细说明。
│  └─doxygen		// doxygen脚本，主要用来维护LwIP的配套文档。对于使用LwIP来说用不到
│      │  generate.bat
│      │  generate.sh
│      │  lwip.Doxyfile
│      │  main_page.h
│      │  lwip.Doxyfile.cmake.in
│      └─output
│              index.html
├─src /* 源码文件部分下面独立详细说明 */
│  │  Filelists.mk
│  │  FILES		// 主要记录了该目录下每个文件、目录的用途
│  ├─api
│  │      api_lib.c
│  │      api_msg.c
│  │      err.c
│  │      netbuf.c
│  │      netdb.c
│  │      netifapi.c
│  │      sockets.c
│  │      tcpip.c
│  ├─apps
│  │  ├─httpd
│  │  │  │  fs.c
│  │  │  │  fsdata.c
│  │  │  │  fsdata.h
│  │  │  │  httpd.c
│  │  │  │  httpd_structs.h
│  │  │  ├─fs
│  │  │  │  │  404.html
│  │  │  │  │  index.html
│  │  │  │  └─img
│  │  │  │          sics.gif
│  │  │  └─makefsdata
│  │  │          makefsdata
│  │  │          makefsdata.c
│  │  │          readme.txt
│  │  ├─lwiperf
│  │  │      lwiperf.c
│  │  ├─mdns
│  │  │      mdns.c
│  │  ├─mqtt
│  │  │      mqtt.c
│  │  ├─netbiosns
│  │  │      netbiosns.c
│  │  ├─snmp
│  │  │      snmpv3.c
│  │  │      snmpv3_dummy.c
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
│  │  │      snmp_table.c
│  │  │      snmp_threadsync.c
│  │  │      snmp_traps.c
│  │  ├─sntp
│  │  │      sntp.c
│  │  └─tftp
│  │          tftp_server.c
│  ├─core
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
│  │  ├─ipv4
│  │  │      autoip.c
│  │  │      dhcp.c
│  │  │      etharp.c
│  │  │      icmp.c
│  │  │      igmp.c
│  │  │      ip4.c
│  │  │      ip4_addr.c
│  │  │      ip4_frag.c
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
│  ├─include
│  │  ├─lwip
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
│  │  │  │  igmp.h
│  │  │  │  inet.h
│  │  │  │  inet_chksum.h
│  │  │  │  init.h
│  │  │  │  ip.h
│  │  │  │  ip4.h
│  │  │  │  ip4_addr.h
│  │  │  │  ip4_frag.h
│  │  │  │  ip6.h
│  │  │  │  ip6_addr.h
│  │  │  │  ip6_frag.h
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
│  │  │  │  tcpip.h
│  │  │  │  timeouts.h
│  │  │  │  udp.h
│  │  │  ├─apps
│  │  │  │      FILES
│  │  │  │      fs.h
│  │  │  │      httpd.h
│  │  │  │      httpd_opts.h
│  │  │  │      lwiperf.h
│  │  │  │      mdns.h
│  │  │  │      mdns_opts.h
│  │  │  │      mdns_priv.h
│  │  │  │      mqtt.h
│  │  │  │      mqtt_opts.h
│  │  │  │      netbiosns.h
│  │  │  │      netbiosns_opts.h
│  │  │  │      snmp.h
│  │  │  │      snmpv3.h
│  │  │  │      snmp_core.h
│  │  │  │      snmp_mib2.h
│  │  │  │      snmp_opts.h
│  │  │  │      snmp_scalar.h
│  │  │  │      snmp_table.h
│  │  │  │      snmp_threadsync.h
│  │  │  │      sntp.h
│  │  │  │      sntp_opts.h
│  │  │  │      tftp_opts.h
│  │  │  │      tftp_server.h
│  │  │  ├─priv
│  │  │  │      api_msg.h
│  │  │  │      memp_priv.h
│  │  │  │      memp_std.h
│  │  │  │      nd6_priv.h
│  │  │  │      tcpip_priv.h
│  │  │  │      tcp_priv.h
│  │  │  └─prot
│  │  │          autoip.h
│  │  │          dhcp.h
│  │  │          dns.h
│  │  │          etharp.h
│  │  │          ethernet.h
│  │  │          icmp.h
│  │  │          icmp6.h
│  │  │          igmp.h
│  │  │          ip.h
│  │  │          ip4.h
│  │  │          ip6.h
│  │  │          mld6.h
│  │  │          nd6.h
│  │  │          tcp.h
│  │  │          udp.h
│  │  ├─netif
│  │  │  │  etharp.h
│  │  │  │  ethernet.h
│  │  │  │  lowpan6.h
│  │  │  │  lowpan6_opts.h
│  │  │  │  slipif.h
│  │  │  └─ppp
│  │  │      │  ccp.h
│  │  │      │  chap-md5.h
│  │  │      │  chap-new.h
│  │  │      │  chap_ms.h
│  │  │      │  eap.h
│  │  │      │  ecp.h
│  │  │      │  eui64.h
│  │  │      │  fsm.h
│  │  │      │  ipcp.h
│  │  │      │  ipv6cp.h
│  │  │      │  lcp.h
│  │  │      │  magic.h
│  │  │      │  mppe.h
│  │  │      │  ppp.h
│  │  │      │  pppapi.h
│  │  │      │  pppcrypt.h
│  │  │      │  pppdebug.h
│  │  │      │  pppoe.h
│  │  │      │  pppol2tp.h
│  │  │      │  pppos.h
│  │  │      │  ppp_impl.h
│  │  │      │  ppp_opts.h
│  │  │      │  upap.h
│  │  │      │  vj.h
│  │  │      └─polarssl
│  │  │              arc4.h
│  │  │              des.h
│  │  │              md4.h
│  │  │              md5.h
│  │  │              sha1.h
│  │  └─posix
│  │      │  errno.h
│  │      │  netdb.h
│  │      └─sys
│  │              socket.h
│  └─netif
│      │  ethernet.c
│      │  ethernetif.c
│      │  FILES
│      │  lowpan6.c
│      │  slipif.c
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
│          └─polarssl
│                  arc4.c
│                  des.c
│                  md4.c
│                  md5.c
│                  README
│                  sha1.c
└─test	// 一些协议栈内核测试程序.在实际使用时一般用不到！可直接删除。
    ├─fuzz
    │  │  config.h
    │  │  fuzz.c
    │  │  lwipopts.h
    │  │  Makefile
    │  │  output_to_pcap.sh
    │  │  README
    │  └─inputs
    │      ├─arp
    │      │      arp_req.bin
    │      ├─icmp
    │      │      icmp_ping.bin
    │      ├─ipv6
    │      │      neighbor_solicitation.bin
    │      │      router_adv.bin
    │      ├─tcp
    │      │      tcp_syn.bin
    │      └─udp
    │              udp_port_5000.bin
    └─unit
        │  lwipopts.h
        │  lwip_check.h
        │  lwip_unittests.c
        ├─core
        │      test_mem.c
        │      test_mem.h
        │      test_pbuf.c
        │      test_pbuf.h
        ├─dhcp
        │      test_dhcp.c
        │      test_dhcp.h
        ├─etharp
        │      test_etharp.c
        │      test_etharp.h
        ├─ip4
        │      test_ip4.c
        │      test_ip4.h
        ├─mdns
        │      test_mdns.c
        │      test_mdns.h
        ├─tcp
        │      tcp_helper.c
        │      tcp_helper.h
        │      test_tcp.c
        │      test_tcp.h
        │      test_tcp_oos.c
        │      test_tcp_oos.h
        └─udp
                test_udp.c
                test_udp.h
