use mutsuki_link::{EndpointId, TransportBudget, local::LocalAddress, local::LocalListener};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "mutsuki-link-manual-server".to_owned());
    let listener = LocalListener::bind(
        &LocalAddress(address.clone()),
        EndpointId::from_bytes([1; 16]),
        TransportBudget::default(),
    )?;
    println!(
        "server-only listener bound to explicit local address {address}; active connections: {}",
        listener.active_connections()
    );
    // An executor-owning host calls `accept`; this example intentionally starts
    // no discovery, pairing UI, or product runtime.
    Ok(())
}
