export const payloadSamples = [
  { name: 'Recycle Bin Cleaner', category: 'Maintenance', size: '22kb', nodes: ['on_launch', 'send_report'], payload: { action: 'clean_recycle_bin' } },
  { name: 'Certificate Expiry Checker', category: 'Maintenance', size: '18kb', nodes: ['local_intel_match'], payload: { action: 'scan_cert_expiry', threshold_days: 30 } },
  { name: 'Registry Patcher', category: 'Security', size: '17kb', nodes: ['ingest_telemetry', 'send_report'], payload: { action: 'registry_patch' } },
  { name: 'Known-Bad Hash Scanner', category: 'Security', size: '31kb', nodes: ['port_scan', 'send_report'], payload: { action: 'hash_scan' } },
  { name: 'Network Change Detector', category: 'Intelligence', size: '14kb', nodes: ['peer_sync', 'append_deadrop'], payload: { action: 'arp_diff' } },
  { name: 'Open Port Mapper', category: 'Recon', size: '13kb', nodes: ['port_scan', 'banner_grab'], payload: { action: 'tcp_connect_scan' } }
];
