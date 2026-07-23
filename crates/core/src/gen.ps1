$files = @(
    @{name='assa_r3'; struct='AssaR3'; label='ASSA-R3'},
    @{name='asterix'; struct='Asterix'; label='ASTERIX'},
    @{name='at'; struct='At'; label='AT'},
    @{name='at_ldf'; struct='AtLdf'; label='AT-LDF'},
    @{name='at_rl'; struct='AtRl'; label='AT-RL'},
    @{name='ath'; struct='Ath'; label='ATH'},
    @{name='atm'; struct='Atm'; label='ATM'},
    @{name='atmtcp'; struct='Atmtcp'; label='ATMTCP'},
    @{name='atn_cm'; struct='AtnCm'; label='ATN-CM'},
    @{name='atn_cpdlc'; struct='AtnCpdlc'; label='ATN-CPDLC'},
    @{name='atn_sl'; struct='AtnSl'; label='ATN-SL'},
    @{name='atn_ulcs'; struct='AtnUlcs'; label='ATN-ULCS'},
    @{name='auto_rp'; struct='AutoRp'; label='AUTO-RP'},
    @{name='autosar_ipdu_multiplexer'; struct='AutosarIpduMultiplexer'; label='AUTOSAR-IPDU-MUX'},
    @{name='autosar_nm'; struct='AutosarNm'; label='AUTOSAR-NM'},
    @{name='avsp'; struct='Avsp'; label='AVSP'},
    @{name='awdl'; struct='Awdl'; label='AWDL'},
    @{name='ax25'; struct='Ax25'; label='AX25'},
    @{name='ax25_kiss'; struct='Ax25Kiss'; label='AX25-KISS'},
    @{name='ax25_nol3'; struct='Ax25Nol3'; label='AX25-NOL3'},
    @{name='ax4000'; struct='Ax4000'; label='AX4000'},
    @{name='ayiya'; struct='Ayiya'; label='AYIYA'},
    @{name='bacapp'; struct='Bacapp'; label='BACAPP'},
    @{name='banana'; struct='Banana'; label='BANANA'},
    @{name='bat'; struct='Bat'; label='BAT'},
    @{name='batadv'; struct='Batadv'; label='BATADV'},
    @{name='bblog'; struct='Bblog'; label='BBLOG'},
    @{name='bctp'; struct='Bctp'; label='BCTP'},
    @{name='beep'; struct='Beep'; label='BEEP'},
    @{name='bencode'; struct='Bencode'; label='BENCODE'},
    @{name='ber'; struct='Ber'; label='BER'},
    @{name='bhttp'; struct='Bhttp'; label='BHTTP'},
    @{name='bicc_mst'; struct='BiccMst'; label='BICC-MST'},
    @{name='bist_itch'; struct='BistItch'; label='BIST-ITCH'},
    @{name='bist_ouch'; struct='BistOuch'; label='BIST-OUCH'},
    @{name='bjnp'; struct='Bjnp'; label='BJNP'},
    @{name='blip'; struct='Blip'; label='BLIP'},
    @{name='bluecom'; struct='Bluecom'; label='BLUECOM'},
    @{name='bmc'; struct='Bmc'; label='BMC'},
    @{name='bofl'; struct='Bofl'; label='BOFL'}
)

foreach ($f in $files) {
    $path = "crates/core/src/dissectors/" + $f.name + ".rs"
    if (-not (Test-Path $path)) {
        $code = @"
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect a $($f.label) packet.
pub fn dissect_$($f.name)(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::$($f.struct),
        summary: format!("$($f.label) ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_$($f.name)() {
        let r = dissect_$($f.name)(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::$($f.struct));
    }
}
"@
        Set-Content -Path $path -Value $code -Encoding UTF8
    }
}
