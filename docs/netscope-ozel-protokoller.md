# Netscope'a Ozgu Protokoller & Protokol Yonetimi Rehberi

> Bu belge, Netscope'u Wireshark'tan ayiran ozel protokolleri listeler ve
> binlerce protokolun cakismadan, karisiklika yol acmadan yonetilebilmesi icin
> gereken senior-seviye muhendislik rehberini icerir.
>
> **Tarih:** 2026-07-23
> **Netscope Toplam Dissector:** 703
> **Wireshark Toplam Dissector:** 1696
> **Netscope'a Ozgu Protokol:** 429

---

## Icindekiler

1. [Netscope'a Ozgu Protokoller (Tam Liste)](#netscope-a-ozgu-protokoller)
2. [Protokol Isimlendirme Konvansiyonlari](#protokol-isimlendirme-konvansiyonlari)
3. [Dosya Yapisi ve Modularite Kurallari](#dosya-yapisi-ve-modularite-kurallari)
4. [Cakisma Onleme Stratejisi](#cakisma-onleme-stratejisi)
5. [Registry Yonetimi](#registry-yonetimi)
6. [Port Binding Kurallari](#port-binding-kurallari)
7. [Test ve Dogrulama Protokolu](#test-ve-dogrulama-protokolu)
8. [Versiyon ve Deprecation Politikasi](#versiyon-ve-deprecation-politikasi)

---

## Netscope'a Ozgu Protokoller

Asagidaki protokoller Wireshark'ta **bulunmayan**, Netscope'un ozel olarak destekledigi dissector'lardir. Toplam **429** adet benzersiz protokol asagida kategorize edilmistir.

### 5G / Telekomunikasyon (24 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `cap_gsm` |
| [ ] | 2 | `dsrc_v2x` |
| [ ] | 3 | `e1ap_ext` |
| [ ] | 4 | `f1ap_ext` |
| [ ] | 5 | `fiveg_n1` |
| [ ] | 6 | `fiveg_n10` |
| [ ] | 7 | `fiveg_n11` |
| [ ] | 8 | `fiveg_n12` |
| [ ] | 9 | `fiveg_n13` |
| [ ] | 10 | `fiveg_n15` |
| [ ] | 11 | `fiveg_n2` |
| [ ] | 12 | `fiveg_n22` |
| [ ] | 13 | `fiveg_n3` |
| [ ] | 14 | `fiveg_n4` |
| [ ] | 15 | `fiveg_n7` |
| [ ] | 16 | `fiveg_n8` |
| [ ] | 17 | `gtp_sv` |
| [ ] | 18 | `gtpprime` |
| [ ] | 19 | `map_gsm` |
| [ ] | 20 | `nb_iot_nas` |
| [ ] | 21 | `ngap_common` |
| [ ] | 22 | `w1ap` |
| [ ] | 23 | `x2ap_ext` |
| [ ] | 24 | `xnap_ext` |

### Endustriyel Otomasyon / OT (68 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `ads` |
| [ ] | 2 | `autosar_pdu` |
| [ ] | 3 | `bacnet_mstp` |
| [ ] | 4 | `bacnet_sc` |
| [ ] | 5 | `can` |
| [ ] | 6 | `can_xl` |
| [ ] | 7 | `canopen_fd` |
| [ ] | 8 | `cc_link_ie_control` |
| [ ] | 9 | `cclink_ie` |
| [ ] | 10 | `cclink_ie_field_basic` |
| [ ] | 11 | `cip_motion` |
| [ ] | 12 | `cip_safety` |
| [ ] | 13 | `codesys` |
| [ ] | 14 | `controlnet` |
| [ ] | 15 | `cpri` |
| [ ] | 16 | `dali` |
| [ ] | 17 | `dlr` |
| [ ] | 18 | `dnp3` |
| [ ] | 19 | `dnp3_tcp` |
| [ ] | 20 | `docan` |
| [ ] | 21 | `erps` |
| [ ] | 22 | `ethercat` |
| [ ] | 23 | `ethercat_coe` |
| [ ] | 24 | `ethercat_foe` |
| [ ] | 25 | `ethercat_mailbox` |
| [ ] | 26 | `ethercat_soe` |
| [ ] | 27 | `ff_hse` |
| [ ] | 28 | `fins` |
| [ ] | 29 | `focas` |
| [ ] | 30 | `foundation_fieldbus_h1` |
| [ ] | 31 | `g3_plc` |
| [ ] | 32 | `gbt_19582` |
| [ ] | 33 | `gbt_20414` |
| [ ] | 34 | `gbt26982` |
| [ ] | 35 | `hart_ip_v2` |
| [ ] | 36 | `hart_wireless` |
| [ ] | 37 | `iec_asdu` |
| [ ] | 38 | `iec101` |
| [ ] | 39 | `iec60870_5_103` |
| [ ] | 40 | `iec61850_8_1` |
| [ ] | 41 | `iec61850_9_2` |
| [ ] | 42 | `isa100_11a` |
| [ ] | 43 | `isotp` |
| [ ] | 44 | `j1708` |
| [ ] | 45 | `mechatrolink_iii` |
| [ ] | 46 | `modbus` |
| [ ] | 47 | `modbus_ascii_ext` |
| [ ] | 48 | `modbus_rtu` |
| [ ] | 49 | `most` |
| [ ] | 50 | `obd2` |
| [ ] | 51 | `opc_ua_pubsub` |
| [ ] | 52 | `opcua` |
| [ ] | 53 | `pccc` |
| [ ] | 54 | `pn_dcp` |
| [ ] | 55 | `pn_ptcp` |
| [ ] | 56 | `powerlink` |
| [ ] | 57 | `prime_plc` |
| [ ] | 58 | `profibus_dp` |
| [ ] | 59 | `profibus_pa` |
| [ ] | 60 | `profinet` |
| [ ] | 61 | `profinet_cba` |
| [ ] | 62 | `profisafe` |
| [ ] | 63 | `roc_plus` |
| [ ] | 64 | `secoc` |
| [ ] | 65 | `slmp` |
| [ ] | 66 | `toyopuc` |
| [ ] | 67 | `uadp` |
| [ ] | 68 | `varan` |

### Veritabani / Veri Depolama (30 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `aerospike` |
| [ ] | 2 | `arangodb` |
| [ ] | 3 | `cassandra` |
| [ ] | 4 | `clickhouse` |
| [ ] | 5 | `couchdb` |
| [ ] | 6 | `druid` |
| [ ] | 7 | `firebird` |
| [ ] | 8 | `hbase` |
| [ ] | 9 | `impala` |
| [ ] | 10 | `influxdb` |
| [ ] | 11 | `informix` |
| [ ] | 12 | `ingres` |
| [ ] | 13 | `maxdb` |
| [ ] | 14 | `memcached` |
| [ ] | 15 | `memcached_bin` |
| [ ] | 16 | `mongodb` |
| [ ] | 17 | `netezza` |
| [ ] | 18 | `orientdb` |
| [ ] | 19 | `questdb` |
| [ ] | 20 | `redis` |
| [ ] | 21 | `redis_cluster` |
| [ ] | 22 | `rethinkdb` |
| [ ] | 23 | `saphana` |
| [ ] | 24 | `tarantool` |
| [ ] | 25 | `tdengine` |
| [ ] | 26 | `teradata` |
| [ ] | 27 | `tikv` |
| [ ] | 28 | `trino` |
| [ ] | 29 | `vertica` |
| [ ] | 30 | `victoriametrics` |

### Mesajlasma / Kuyruk / Streaming (12 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `amqp1` |
| [ ] | 2 | `fluentd` |
| [ ] | 3 | `mqttsn` |
| [ ] | 4 | `nanomsg_sp` |
| [ ] | 5 | `nsq` |
| [ ] | 6 | `pulsar` |
| [ ] | 7 | `rabbitmq_stream` |
| [ ] | 8 | `solace_smf` |
| [ ] | 9 | `stomp` |
| [ ] | 10 | `tibco_ems` |
| [ ] | 11 | `tibco_rv` |
| [ ] | 12 | `vector_native` |

### Gozlemlenebilirlik / Monitoring (23 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `collectd_v5` |
| [ ] | 2 | `etcd` |
| [ ] | 3 | `ganglia` |
| [ ] | 4 | `ganglia_gmetad` |
| [ ] | 5 | `gnmi` |
| [ ] | 6 | `graphite` |
| [ ] | 7 | `graphite_pickle` |
| [ ] | 8 | `icinga2` |
| [ ] | 9 | `jaeger` |
| [ ] | 10 | `loki_push` |
| [ ] | 11 | `munin` |
| [ ] | 12 | `nagios_ndo` |
| [ ] | 13 | `nagios_nsca` |
| [ ] | 14 | `netdata` |
| [ ] | 15 | `opentsdb` |
| [ ] | 16 | `otlp_grpc` |
| [ ] | 17 | `otlp_http` |
| [ ] | 18 | `prometheus_rw` |
| [ ] | 19 | `sensu` |
| [ ] | 20 | `splunk_s2s` |
| [ ] | 21 | `statsd` |
| [ ] | 22 | `telegraf_influxv2` |
| [ ] | 23 | `zipkin` |

### IoT / Akilli Ev / Wireless (25 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `att` |
| [ ] | 2 | `ble_att` |
| [ ] | 3 | `ble_gatt` |
| [ ] | 4 | `ble_smp` |
| [ ] | 5 | `coap_tcp` |
| [ ] | 6 | `enocean` |
| [ ] | 7 | `esphome` |
| [ ] | 8 | `homekit` |
| [ ] | 9 | `insteon` |
| [ ] | 10 | `knx_rf` |
| [ ] | 11 | `knx_tp` |
| [ ] | 12 | `lorawan_mac` |
| [ ] | 13 | `lwm2m` |
| [ ] | 14 | `m_bus_wireless` |
| [ ] | 15 | `matter_ip` |
| [ ] | 16 | `semtech_lora` |
| [ ] | 17 | `sigfox_uplink` |
| [ ] | 18 | `thread_mesh` |
| [ ] | 19 | `x10` |
| [ ] | 20 | `zigbee` |
| [ ] | 21 | `zigbee_gp` |
| [ ] | 22 | `zigbee_nwk` |
| [ ] | 23 | `zigbee_zcl` |
| [ ] | 24 | `zwave` |
| [ ] | 25 | `zwave_command` |

### VPN / Tunel / Guvenlik (20 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `dtls_srtp` |
| [ ] | 2 | `fastd_vpn` |
| [ ] | 3 | `ikev2` |
| [ ] | 4 | `ipsec_ikev1` |
| [ ] | 5 | `ipsec_ikev2` |
| [ ] | 6 | `isakmp` |
| [ ] | 7 | `nebula` |
| [ ] | 8 | `obfs4` |
| [ ] | 9 | `openconnect` |
| [ ] | 10 | `openvpn_tcp` |
| [ ] | 11 | `shadowsocks` |
| [ ] | 12 | `softether` |
| [ ] | 13 | `softether_vpn` |
| [ ] | 14 | `sstp_vpn` |
| [ ] | 15 | `tailscale_derp` |
| [ ] | 16 | `vmess` |
| [ ] | 17 | `wireguard_handshake` |
| [ ] | 18 | `yggdrasil_mesh` |
| [ ] | 19 | `zerotier` |
| [ ] | 20 | `zerotier_control` |

### Dagitik Sistemler / Cluster (19 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `beegfs` |
| [ ] | 2 | `beegfs_rdma` |
| [ ] | 3 | `coda` |
| [ ] | 4 | `consul_rpc` |
| [ ] | 5 | `gluster_rpc` |
| [ ] | 6 | `gpfs_nsd` |
| [ ] | 7 | `hadooprpc` |
| [ ] | 8 | `hdfs_data` |
| [ ] | 9 | `lustre_lnet` |
| [ ] | 10 | `memberlist` |
| [ ] | 11 | `moosefs` |
| [ ] | 12 | `mpi_wire` |
| [ ] | 13 | `orangefs` |
| [ ] | 14 | `pmix` |
| [ ] | 15 | `sheepdog` |
| [ ] | 16 | `slurm_rpc` |
| [ ] | 17 | `syncthing` |
| [ ] | 18 | `ucx_hpc` |
| [ ] | 19 | `voldemort` |

### Multimedya / AV over IP (18 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `aes67` |
| [ ] | 2 | `avdecc` |
| [ ] | 3 | `avtp` |
| [ ] | 4 | `cobranet` |
| [ ] | 5 | `dante_audio` |
| [ ] | 6 | `mpegts` |
| [ ] | 7 | `ndi_video` |
| [ ] | 8 | `rist` |
| [ ] | 9 | `rist_main_profile` |
| [ ] | 10 | `rtmp` |
| [ ] | 11 | `rtp_midi_ext` |
| [ ] | 12 | `rtpmidi` |
| [ ] | 13 | `rtsp_interleaved` |
| [ ] | 14 | `spx` |
| [ ] | 15 | `srt_control` |
| [ ] | 16 | `srt_transport` |
| [ ] | 17 | `srtp_ge` |
| [ ] | 18 | `st2110` |

### Enerji / Akilli Sayac (8 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `dlms` |
| [ ] | 2 | `esmc` |
| [ ] | 3 | `mbus` |
| [ ] | 4 | `rgoose` |
| [ ] | 5 | `wmbus` |
| [ ] | 6 | `wmbus_c_mode` |
| [ ] | 7 | `wmbus_s_mode` |
| [ ] | 8 | `wmbus_t_mode` |

### Network Altyapi Uzantilari (34 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `batman` |
| [ ] | 2 | `ccp` |
| [ ] | 3 | `chaosnet` |
| [ ] | 4 | `chap` |
| [ ] | 5 | `cldap` |
| [ ] | 6 | `dec_lat` |
| [ ] | 7 | `dec_mop` |
| [ ] | 8 | `decnet` |
| [ ] | 9 | `dhcpfo` |
| [ ] | 10 | `dns_over_quic` |
| [ ] | 11 | `dns_tcp` |
| [ ] | 12 | `dnscrypt` |
| [ ] | 13 | `erspan` |
| [ ] | 14 | `evpn_ext` |
| [ ] | 15 | `fou` |
| [ ] | 16 | `geneve_ext` |
| [ ] | 17 | `gue` |
| [ ] | 18 | `isatap` |
| [ ] | 19 | `l2cap` |
| [ ] | 20 | `l2tpv3` |
| [ ] | 21 | `link_oam` |
| [ ] | 22 | `macctrl` |
| [ ] | 23 | `mpls_in_udp` |
| [ ] | 24 | `nsh_ext` |
| [ ] | 25 | `nvgre_ext` |
| [ ] | 26 | `rarp` |
| [ ] | 27 | `six_to_four` |
| [ ] | 28 | `snap` |
| [ ] | 29 | `sr_mpls` |
| [ ] | 30 | `srv6_ext` |
| [ ] | 31 | `stp` |
| [ ] | 32 | `stt_ext` |
| [ ] | 33 | `vxlan_gpe_nsh` |
| [ ] | 34 | `vxlangpe` |

### Web / API / RPC (18 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `activitypub` |
| [ ] | 2 | `as2_edi` |
| [ ] | 3 | `caldav_carddav` |
| [ ] | 4 | `cwmp` |
| [ ] | 5 | `gemini_proto` |
| [ ] | 6 | `http_body` |
| [ ] | 7 | `lmtp` |
| [ ] | 8 | `matrix_federation` |
| [ ] | 9 | `pop3` |
| [ ] | 10 | `restconf` |
| [ ] | 11 | `scep` |
| [ ] | 12 | `soap` |
| [ ] | 13 | `upnp_soap` |
| [ ] | 14 | `usp` |
| [ ] | 15 | `webdav` |
| [ ] | 16 | `wpad` |
| [ ] | 17 | `wsd` |
| [ ] | 18 | `xwap` |

### Oyun / Eglence (2 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `minecraft` |
| [ ] | 2 | `mumble` |

### Dosya Sistemleri / Ag Paylasimi (7 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `nfs_callback` |
| [ ] | 2 | `nvmeof` |
| [ ] | 3 | `oftp` |
| [ ] | 4 | `pnfs` |
| [ ] | 5 | `roce` |
| [ ] | 6 | `roce_v2` |
| [ ] | 7 | `srp_rdma` |

### Diger (Kategorize Edilmemis) (121 adet)

| | # | Protokol |
|---|---|----------|
| [ ] | 1 | `adsb` |
| [ ] | 2 | `amx_icsp` |
| [ ] | 3 | `artemis_core` |
| [ ] | 4 | `beanstalk` |
| [ ] | 5 | `beats` |
| [ ] | 6 | `bindings` |
| [ ] | 7 | `bolt` |
| [ ] | 8 | `bsap` |
| [ ] | 9 | `ceph_msgr2` |
| [ ] | 10 | `clamav` |
| [ ] | 11 | `crestron_cip` |
| [ ] | 12 | `der` |
| [ ] | 13 | `dht` |
| [ ] | 14 | `diameter_cx` |
| [ ] | 15 | `diameter_gx` |
| [ ] | 16 | `diameter_gy` |
| [ ] | 17 | `diameter_sh` |
| [ ] | 18 | `dicom` |
| [ ] | 19 | `edp` |
| [ ] | 20 | `epics_ca` |
| [ ] | 21 | `epics_pva` |
| [ ] | 22 | `est` |
| [ ] | 23 | `ethernet` |
| [ ] | 24 | `ethernet_powerlink_v2` |
| [ ] | 25 | `extron_sis` |
| [ ] | 26 | `fc2` |
| [ ] | 27 | `fcoe_initialization` |
| [ ] | 28 | `fdp` |
| [ ] | 29 | `fox` |
| [ ] | 30 | `gtpv1u` |
| [ ] | 31 | `gtpv2c` |
| [ ] | 32 | `guacamole` |
| [ ] | 33 | `h225ras` |
| [ ] | 34 | `homeplug_green_phy` |
| [ ] | 35 | `ibmmq` |
| [ ] | 36 | `ica` |
| [ ] | 37 | `ident` |
| [ ] | 38 | `iscsi_login` |
| [ ] | 39 | `iwarp` |
| [ ] | 40 | `kermit` |
| [ ] | 41 | `linktypes` |
| [ ] | 42 | `lontalk` |
| [ ] | 43 | `lonworks_ip` |
| [ ] | 44 | `managesieve` |
| [ ] | 45 | `mdns` |
| [ ] | 46 | `mercurial` |
| [ ] | 47 | `milter` |
| [ ] | 48 | `mosh` |
| [ ] | 49 | `mrp` |
| [ ] | 50 | `mrp_registration` |
| [ ] | 51 | `mssqlbrowser` |
| [ ] | 52 | `mtconnect` |
| [ ] | 53 | `nbds` |
| [ ] | 54 | `nbns` |
| [ ] | 55 | `netbeui` |
| [ ] | 56 | `netconf` |
| [ ] | 57 | `ninep` |
| [ ] | 58 | `nis_yp` |
| [ ] | 59 | `nmea` |
| [ ] | 60 | `nomachine_nx` |
| [ ] | 61 | `nrpe` |
| [ ] | 62 | `ntlm` |
| [ ] | 63 | `of_config` |
| [ ] | 64 | `onvif` |
| [ ] | 65 | `openflow_v15` |
| [ ] | 66 | `openr` |
| [ ] | 67 | `oran_e1` |
| [ ] | 68 | `ovsdb` |
| [ ] | 69 | `ovsdb_json` |
| [ ] | 70 | `pap` |
| [ ] | 71 | `pcoip` |
| [ ] | 72 | `pdcp` |
| [ ] | 73 | `perforce` |
| [ ] | 74 | `pkix` |
| [ ] | 75 | `postgres` |
| [ ] | 76 | `q_sys_control` |
| [ ] | 77 | `qpack` |
| [ ] | 78 | `radiotap` |
| [ ] | 79 | `radmin` |
| [ ] | 80 | `relp` |
| [ ] | 81 | `rexec` |
| [ ] | 82 | `rfb` |
| [ ] | 83 | `riak` |
| [ ] | 84 | `rlc` |
| [ ] | 85 | `rpkirtr` |
| [ ] | 86 | `rrc_lte` |
| [ ] | 87 | `rrc_nr` |
| [ ] | 88 | `rwho` |
| [ ] | 89 | `s7comm_plus` |
| [ ] | 90 | `safetynet_p` |
| [ ] | 91 | `sap_announce` |
| [ ] | 92 | `sasl` |
| [ ] | 93 | `sbcap` |
| [ ] | 94 | `sercos` |
| [ ] | 95 | `sercos_iii` |
| [ ] | 96 | `sigtran` |
| [ ] | 97 | `sixlowpan` |
| [ ] | 98 | `slp` |
| [ ] | 99 | `small_services` |
| [ ] | 100 | `someip_tp` |
| [ ] | 101 | `sonmp` |
| [ ] | 102 | `source_query` |
| [ ] | 103 | `spamd` |
| [ ] | 104 | `spb` |
| [ ] | 105 | `ssdp` |
| [ ] | 106 | `svn` |
| [ ] | 107 | `tacacs_legacy` |
| [ ] | 108 | `tango_controls` |
| [ ] | 109 | `tcp_analysis` |
| [ ] | 110 | `tsp_timestamp` |
| [ ] | 111 | `turn` |
| [ ] | 112 | `utp` |
| [ ] | 113 | `uucp` |
| [ ] | 114 | `vnet_ip` |
| [ ] | 115 | `wap_wsp_wtp` |
| [ ] | 116 | `wibree` |
| [ ] | 117 | `wlan` |
| [ ] | 118 | `xns` |
| [ ] | 119 | `zabbix_active` |
| [ ] | 120 | `zmodem` |
| [ ] | 121 | `zookeeper` |

---

## Protokol Isimlendirme Konvansiyonlari

Binlerce protokolun karismamasi icin asagidaki kurallara **kati** sekilde uyulmalidir.

### Dosya Adlandirma

`
crates/core/src/dissectors/<protokol_adi>.rs
`

| Kural | Ornek | Yanlis |
|-------|-------|--------|
| Tamami kucuk harf | modbus_rtu.rs | ModbusRTU.rs |
| Kelimeler _ ile ayrilir | dns_over_quic.rs | dns-over-quic.rs, dnsoverquic.rs |
| Kisaltmalar kucuk harf | opc_ua_pubsub.rs | OPC_UA_PubSub.rs |
| Versiyon numaralari direkt | mqp1.rs, http2.rs | mqp_v1.rs, http_2.rs |
| Alt-protokoller _ ile bagli | ethercat_coe.rs | ethercat-coe.rs |
| Uzantilar _ext son eki | geneve_ext.rs | geneve_extensions.rs |

### Enum Variant Adlandirma (registry.rs)

`ust
// Dosya adi:    modbus_rtu.rs
// Enum variant: ModbusRtu
// Display name: "Modbus RTU"
// Filter alias: ["modbus-rtu", "modbusrtu"]
`

| Dosya Adi | Enum Variant | Display | Alias'lar |
|-----------|-------------|---------|-----------|
| dns_over_quic.rs | DnsOverQuic | "DNS/QUIC" | ["doq", "dns-quic"] |
| ethercat_coe.rs | EthercatCoe | "EtherCAT CoE" | ["ecat-coe"] |
| iveg_n1.rs | FivegN1 | "5G N1" | ["5g-n1"] |
| opc_ua_pubsub.rs | OpcUaPubsub | "OPC UA Pub/Sub" | ["opcua-pubsub"] |

### Isim Cakisma Onleme Matrisi

| Durum | Cozum | Ornek |
|-------|-------|-------|
| Ayni isimli farkli protokoller | Prefiks ekle | cisco_cdp.rs vs 
ortel_cdp.rs |
| Protokolun TCP vs UDP varyanti | _tcp / _udp son eki | dns.rs, dns_tcp.rs |
| Versiyon farklari | Versiyon numarasi | http.rs, http2.rs |
| Alt-protokoller | Ust protokol prefiksi | ethercat.rs, ethercat_coe.rs |
| Vendor-specific uzantilar | Vendor prefiksi | cisco_erspan.rs |
| Mod/profil farklari | Aciklayici son ek | wmbus_c_mode.rs, wmbus_s_mode.rs |

---

## Dosya Yapisi ve Modularite Kurallari

### Tek Dosya = Tek Protokol

Her .rs dosyasi **tam olarak bir** protokol dissector'u icerir. Istisnalar:

- indings.rs â€” port-to-dissector mapping tablosu (dissector degil)
- linktypes.rs â€” pcap link-type dispatching (dissector degil)
- 	cp_analysis.rs â€” TCP flow analysis helper (dissector degil)

### Dosya Boyut Limitleri

| Boyut | Aksiyon |
|-------|---------|
| < 500 satir | Normal â€” tek dosya |
| 500-2000 satir | Kabul edilebilir (TLS, TCP gibi karmasik protokoller) |
| > 2000 satir | Alt-modullere bol (someip.rs + someip_sd.rs + someip_tp.rs) |

### Zorunlu Dosya Yapisi

`ust
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use crate::models::Protocol;
use super::DissectedResult;

/// Tek satirlik protokol aciklamasi.
///
/// Detayli aciklama: protokolun amaci, hangi katmanda calistigi,
/// hangi portlari kullandigi, RFC veya standart numarasi.
pub fn dissect_<protokol>(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // ...
}

#[cfg(test)]
mod tests {
    use super::*;
    // En az 1 basarili parse testi
    // En az 1 malformed input testi
    // En az 1 bos payload testi
}
`

---

## Cakisma Onleme Stratejisi

### 1. Port Cakisma Tablosu

Ayni portu kullanan protokoller icin **oncelik sirasi** zorunludur:

`
Port 502:  Modbus (1. oncelik) vs DNP3-TCP (icerik kontrolu ile)
Port 443:  TLS (1.) > HTTP/2 (2.) > QUIC (3., UDP)
Port 4840: OPC UA (1.) > OPC UA Pub/Sub (icerik kontrolu ile)
`

**Kural:** Ayni porta yeni protokol eklenmeden once indings.rs'deki
mevcut tum baglantilari kontrol et. Cakisma varsa content guard ekle.

### 2. EtherType Cakisma Kontrolu

Yeni bir EtherType eklenmeden once:

`ash
# Mevcut EtherType kullanimlarini kontrol et
grep -rn "0x88" crates/core/src/dissectors/ethernet.rs
grep -rn "EtherType" crates/core/src/dissectors/
`

### 3. Protocol Enum Benzersizlik Garantisi

egistry.rs'deki protocols! macro'su derleme zamaninda benzersizligi garanti eder:

- Her $variant Rust enum variant'idir â€” tekrar derleme hatasidir
- Her $display stringe eslenir â€” tekrar runtime assertion'dir
- Her alias is_lexable_token() ile dogrulanir

### 4. CI/CD Kontrolleri (Onerilir)

`yaml
# .github/workflows/protocol-check.yml
- name: Dissector benzersizlik kontrolu
  run: |
    # Ayni dosya adinda iki dissector olmadigini dogrula
    find crates/core/src/dissectors/ -name "*.rs" | sort | uniq -d | grep . && exit 1 || true

    # Registry'deki tum variant'larin benzersiz oldugunu dogrula
    cargo test -p netscope-core registry_variants_are_unique

    # Port binding'lerde cakisma olmadigini dogrula
    cargo test -p netscope-core no_duplicate_port_bindings
`

---

## Registry Yonetimi

### Yeni Protokol Ekleme Adim Adim

`
1. dissectors/<protokol>.rs            â€” dissector yaz
2. dissectors.rs                       â€” pub mod <protokol>;
3. registry.rs â†’ protocols! macro      â€” enum variant ekle
4. bindings.rs                         â€” port binding ekle
5. education/lesson.rs                 â€” egitim metni ekle (zorunlu â€” exhaustive match)
6. cargo test                          â€” tum testler gecmeli
7. cargo clippy -- -D warnings         â€” sifir uyari
`

### Registry Satir Formati

`ust
ProtokolAdi {
    doc:       "Tek satirlik doc comment",
    display:   "Kullaniciya gorunen ad",
    color:     0xRRGGBB,          // TUI renk kodu (benzersiz olmali)
    transport: Tcp,               // Tcp | Udp | Icmp | Arp | Other
    rank:      42,                // Oncelik sirasi (dusuk = oncelikli)
    aliases:   ["kisa-ad", "alternatif"],
    blurb:     "Filtre balonunda gorunecek kisa aciklama",
}
`

### Renk Cakisma Onleme

- Ayni kategorideki protokoller yakin tonlarda olmali (ornek: tum DB'ler mor tonlari)
- Farkli kategoriler farkli renk ailesinden secilmeli
- cargo test color_uniqueness testi eklenmeli

---

## Port Binding Kurallari

### bindings.rs Tablosu

`ust
// TCP binding'ler sirali tutulmali (binary search icin)
pub const TCP_BINDINGS: &[(u16, DissectorFn)] = &[
    (80,   dissect_http),
    (443,  dissect_tls),
    (502,  dissect_modbus),
    // ... port sirasina gore
];
`

| Kural | Aciklama |
|-------|----------|
| Siralama | Tablo port numarasina gore **artan** sirada olmali |
| Tekil port | Her port en fazla bir dissector'e baglanabilir |
| Ephemeral port | 49152+ portlar icerik kontrolu (content guard) gerektirir |
| Range binding | Ayri bir PORT_RANGES tablosunda tutulur |
| Structural sniff | Port'suz tespitler SNIFFERS tablosunda tutulur |

### Oncelik Sirasi (Dispatch Precedence)

`
1. Port + content guard  (en spesifik)
2. Exact port match      (bu tablo)
3. Port ranges           (BitTorrent 6881-6889 gibi)
4. Structural sniffs     (port'suz, framing'e dayali)
5. User plugins          (hicbir zaman built-in'i golgelemez)
`

---

## Test ve Dogrulama Protokolu

### Her Dissector Icin Minimum Test Seti

`ust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_packet() {
        // Bilinen gecerli paket verisi ile test
    }

    #[test]
    fn handle_malformed_header() {
        // Bozuk header ile panic olmadan donmeli
    }

    #[test]
    fn handle_empty_payload() {
        // Bos veri ile Protocol::Unknown donmeli
    }

    #[test]
    fn handle_truncated_packet() {
        // Yarida kesilmis paket ile graceful donmeli
    }
}
`

### Global Fuzz Testi

dispatch_random_garbage_never_panics testi 1000 rastgele input ile
tum dissector'lerin panic yapmadigini dogrular. Yeni dissector eklerken
bu testin gectiginden emin olun.

### Entegrasyon Testi Checklist

- [ ] cargo test -p netscope-core gecti
- [ ] cargo clippy -p netscope-core -- -D warnings sifir uyari
- [ ] Yeni protokol icin pcap fixture olusturuldu (	ools/gen-fixtures/)
- [ ] education/lesson.rs exhaustive match tamamlandi
- [ ] Port cakismasi yok (mevcut binding'ler kontrol edildi)
- [ ] Display name ve alias'lar benzersiz

---

## Versiyon ve Deprecation Politikasi

### Protokol Yasam Dongusu

`
[Draft] â†’ [Stable] â†’ [Deprecated] â†’ [Removed]
`

| Durum | Anlam | Aksiyon |
|-------|-------|---------|
| Draft | Yeni eklendi, API degisebilir | // DRAFT: API may change yorumu |
| Stable | Production-ready | Normal kullanim |
| Deprecated | Artik onerilmiyor | #[deprecated] attribute + yonlendirme |
| Removed | Koddan cikarildi | Major versiyon artisi gerektirir |

### Breaking Change Politikasi

- **Protocol enum variant silme** â†’ Major versiyon (semver)
- **Display name degistirme** â†’ Minor versiyon + CHANGELOG notu
- **Port binding degistirme** â†’ Minor versiyon + migration guide
- **Yeni protokol ekleme** â†’ Patch versiyon (geriye uyumlu)

### Gelecek Buyume Icin Mimari Notlar

Mevcut yapi ~700 protokolde sorunsuz calisir. 2000+ protokole ulastiginda:

1. **Registry bolunmesi**: protocols! macro'su alt-macro'lara ayrilabilir
   (orn. protocols_industrial!, protocols_telecom!)

2. **Lazy loading**: Nadir kullanilan dissector'ler dynamic loading ile
   yuklenebilir (dlopen veya WASM plugin sistemi)

3. **Kategori bazli derleme**: cargo features ile sadece gereken
   protokol aileleri derlenebilir:
   `	oml
   [features]
   industrial = ["modbus", "profinet", "ethercat", ...]
   telecom = ["5g", "lte", "gsm", ...]
   full = ["industrial", "telecom", "database", ...]
   `

4. **Otomatik cakisma tespiti**: CI'da calisan bir script tum port
   binding'leri, display name'leri ve alias'lari cross-check etmeli

---

> **Not:** Bu belge canli bir dokumandir. Yeni protokoller eklendikce
> ilgili kategoriler guncellenmelidir. Herhangi bir kural degisikligi
> takim onayi gerektirir.