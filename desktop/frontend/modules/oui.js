// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
// netscope Desktop — OUI (MAC vendor) lookup.
//
// The first three bytes of a MAC address are an Organizationally Unique
// Identifier assigned by the IEEE to the hardware maker. This is a CURATED
// subset — the full registry is ~35 000 entries / ~1.5 MB, too heavy to embed —
// covering the consumer, phone, IoT and networking vendors you actually see on
// a home/office WiFi. Anything not listed resolves to null, shown as unknown.
//
// Keys are the uppercase hex of the first three octets, no separators.
const OUI = {
  // Apple (uses hundreds of OUIs; these are among the most common)
  '000393': 'Apple', '001451': 'Apple', '0017F2': 'Apple', '001B63': 'Apple',
  '001EC2': 'Apple', '002332': 'Apple', '002500': 'Apple', '0026BB': 'Apple',
  '3C0754': 'Apple', '3C15C2': 'Apple', '40331A': 'Apple', '542696': 'Apple',
  '7CD1C3': 'Apple', 'A4B197': 'Apple', 'AC87A3': 'Apple', 'B8E856': 'Apple',
  'D0817A': 'Apple', 'F0D1A9': 'Apple', 'F4F15A': 'Apple', 'F8FFC2': 'Apple',
  // Samsung
  '0000F0': 'Samsung', '0007AB': 'Samsung', '0012FB': 'Samsung', '001632': 'Samsung',
  '0021D1': 'Samsung', '5001BB': 'Samsung', '5C0A5B': 'Samsung', '8425DB': 'Samsung',
  'E8508B': 'Samsung', 'F008F1': 'Samsung', 'CC07AB': 'Samsung',
  // Intel (Wi-Fi / NUC)
  '001B21': 'Intel', '001E67': 'Intel', '3CA9F4': 'Intel', '7CB27D': 'Intel',
  '8C1645': 'Intel', 'A0A8CD': 'Intel', 'AC7BA1': 'Intel', 'B4D5BD': 'Intel',
  'E0D55E': 'Intel', 'F8633F': 'Intel', '9CB6D0': 'Intel',
  // Google / Nest / Chromecast
  '3C5AB4': 'Google', '54609D': 'Google', 'A47733': 'Google', 'DA0D68': 'Google',
  'F4F5D8': 'Google', 'F4F5E8': 'Google', '1CF29A': 'Google',
  // Amazon (Echo / Fire / Ring)
  '0806F5': 'Amazon', '44650D': 'Amazon', '68543D': 'Amazon', '74C246': 'Amazon',
  'A002DC': 'Amazon', 'FC65DE': 'Amazon', 'F0272D': 'Amazon',
  // Microsoft (Surface / Xbox)
  '000D3A': 'Microsoft', '0017FA': 'Microsoft', '281878': 'Microsoft',
  '7C1E52': 'Microsoft', 'C83F26': 'Microsoft',
  // Networking gear
  '001018': 'Broadcom', '000C29': 'VMware', '005056': 'VMware', '080027': 'VirtualBox',
  '00050F': 'Cisco', '000142': 'Cisco', '001A2F': 'Cisco',
  '0018F3': 'ASUSTek', '107B44': 'ASUSTek', '2C56DC': 'ASUSTek', '50465D': 'ASUSTek',
  '9C5C8E': 'ASUSTek', 'AC220B': 'ASUSTek', 'D850E6': 'ASUSTek',
  '00146C': 'Netgear', '000FB5': 'Netgear', '008EF2': 'Netgear', '204E7F': 'Netgear',
  '2827BF': 'Netgear', 'A00460': 'Netgear',
  '00195B': 'D-Link', '001CF0': 'D-Link', '0022B0': 'D-Link', 'C8BE19': 'D-Link',
  '000D88': 'TP-Link', '001478': 'TP-Link', '14CC20': 'TP-Link', '5091E3': 'TP-Link',
  '6470F5': 'TP-Link', 'A42BB0': 'TP-Link', 'C46E1F': 'TP-Link', 'EC086B': 'TP-Link',
  '50C7BF': 'TP-Link', '98DED0': 'TP-Link',
  '0018E7': 'Ubiquiti', '002722': 'Ubiquiti', '24A43C': 'Ubiquiti', '44D9E7': 'Ubiquiti',
  '788A20': 'Ubiquiti', 'FCECDA': 'Ubiquiti',
  'B827EB': 'Raspberry Pi', 'DCA632': 'Raspberry Pi', 'E45F01': 'Raspberry Pi',
  '2CCF67': 'Raspberry Pi', '28CDC1': 'Raspberry Pi',
  // Phones / IoT
  '0025BC': 'Huawei', '48435A': 'Huawei', '4C5499': 'Huawei', '80B686': 'Huawei',
  'ACE215': 'Huawei', 'F4C714': 'Huawei',
  '10D07A': 'Xiaomi', '286C07': 'Xiaomi', '3480B3': 'Xiaomi', '640980': 'Xiaomi',
  '742344': 'Xiaomi', '7C1DD9': 'Xiaomi', 'F8A45F': 'Xiaomi',
  '00EABD': 'Sony', '104FA8': 'Sony', '3C0771': 'Sony', 'FC0FE6': 'Sony',
  '001788': 'Philips Hue',
  '18B430': 'Nest', '641666': 'Nest',
  'B0A737': 'Roku', 'CC6DA0': 'Roku', 'DC3A5E': 'Roku', 'D0004B': 'Roku',
  'D052A8': 'Wyze', '2CAA8E': 'Wyze',
  '000E58': 'Sonos', '347E5C': 'Sonos', '5CAAFD': 'Sonos', '949F3E': 'Sonos',
  'B8278A': 'Tesla', '4CFCAA': 'Tesla', '54E019': 'Tesla',
  'FCDBB3': 'Realtek', '525400': 'QEMU',
};

/** Vendor name for a MAC string ("aa:bb:cc:dd:ee:ff") or null if unknown. */
export function macVendor(mac) {
  if (!mac) return null;
  const hex = mac.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  if (hex.length < 6) return null;
  return OUI[hex.slice(0, 6)] || null;
}

/** True if this MAC is locally administered (2nd-least-significant bit of the
 *  first octet set) — i.e. a randomised MAC, not a real burned-in vendor
 *  address. Modern phones randomise per-SSID for privacy, so this is common. */
export function isRandomizedMac(mac) {
  if (!mac) return false;
  const first = parseInt(mac.replace(/[^0-9a-fA-F]/g, '').slice(0, 2), 16);
  return Number.isFinite(first) && (first & 0x02) !== 0;
}
