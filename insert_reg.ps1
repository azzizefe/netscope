$uniqueNames = @(
  'profibus_dp', 'profibus_pa', 'profinet_cba', 'cc_link_ie_control', 'canopen_fd', 'devicenet', 'controlnet', 'hart_ip_v2', 'foundation_fieldbus_h1',
  'bacnet_mstp', 'bacnet_sc', 'lonworks_ip', 'dnp3_tcp', 'iec60870_5_103', 'iec61850_9_2', 'iec61850_8_1', 'ethercat_coe', 'ethercat_soe', 'ethercat_foe',
  'fiveg_n1', 'fiveg_n3', 'fiveg_n7', 'fiveg_n8', 'fiveg_n10', 'fiveg_n12', 'fiveg_n13', 'fiveg_n15', 'fiveg_n22',
  'x2ap_ext', 'xnap_ext', 'gtpv2c', 'diameter_cx', 'diameter_sh', 'diameter_gx', 'diameter_gy', 'map_gsm', 'cap_gsm',
  'geneve_ext', 'vxlan_gpe_nsh', 'stt_ext', 'sr_mpls', 'openflow_v15', 'ovsdb_json',
  'ceph_msgr2', 'gluster_rpc', 'lustre_lnet', 'gpfs_nsd', 'beegfs_rdma', 'iscsi_login', 'nvme_tcp', 'fcoe_initialization', 'roce_v2', 'iwarp',
  'matter_ip', 'thread_mesh', 'zigbee_zcl', 'zigbee_nwk', 'zwave_command', 'ble_att', 'ble_gatt', 'ble_smp', 'lorawan_mac', 'sigfox_uplink',
  'nb_iot_nas', 'homeplug_av', 'homeplug_green_phy', 'g3_plc', 'prime_plc', 'm_bus_wireless', 'wmbus_s_mode', 'wmbus_t_mode', 'wmbus_c_mode', 'dsrc_v2x',
  'rtsp_interleaved', 'rtp_midi_ext', 'srt_control', 'rist_main_profile', 'ndi_video', 'dante_audio', 'q_sys_control', 'crestron_cip', 'amx_icsp', 'extron_sis',
  'openvpn_tcp', 'wireguard_handshake', 'ipsec_ikev1', 'ipsec_ikev2', 'sstp_vpn', 'softether_vpn', 'zerotier_control', 'tailscale_derp', 'fastd_vpn', 'yggdrasil_mesh',
  'modbus_ascii_ext', 'nvgre_ext', 'srv6_ext', 'f1ap_ext', 'e1ap_ext', 'nsh_ext', 'evpn_ext'
)

$regCode = ''

foreach ($n in $uniqueNames) {
  $parts = $n.Split('_')
  $pascal = ''
  foreach ($p in $parts) {
    $pascal += $p.Substring(0,1).ToUpperInvariant() + $p.Substring(1).ToLowerInvariant()
  }
  
  $regCode += @"
    $pascal {
        doc:       "$pascal protocol extension.",
        display:   "$pascal",
        color:     0x2563EB,
        transport: Tcp,
        rank:      3,
        aliases:   ["$n"],
        blurb:     "A $pascal protocol frame.",
    }
"@ + "`n"
}

[System.IO.File]::WriteAllText("reg_code_clean.txt", $regCode, [System.Text.Encoding]::UTF8)

$reg = Get-Content "crates/core/src/registry.rs" -Raw
$app = Get-Content "reg_code_clean.txt" -Raw
$target = "    Usp {"
$idx = $reg.IndexOf($target)
$endIdx = $reg.IndexOf("}", $idx) + 1
$newReg = $reg.Substring(0, $endIdx) + "`n" + $app + $reg.Substring($endIdx)
[System.IO.File]::WriteAllText("crates/core/src/registry.rs", $newReg, [System.Text.Encoding]::UTF8)

Write-Host "REGISTRY_CLEANLY_INSERTED_INSIDE_MACRO"
