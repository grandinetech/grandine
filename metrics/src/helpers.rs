use sysinfo::Networks;

pub fn get_network_bytes() -> (u64, u64) {
    let mut rx_bytes: u64 = 0;
    let mut tx_bytes: u64 = 0;

    let networks = Networks::new_with_refreshed_list();
    for (interface_name, data) in &networks {
        if interface_name != "lo" {
            rx_bytes = rx_bytes.saturating_add(data.total_received());
            tx_bytes = tx_bytes.saturating_add(data.total_transmitted());
        }
    }

    (rx_bytes, tx_bytes)
}
