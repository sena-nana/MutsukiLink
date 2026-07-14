use mutsuki_link::{
    ConnectContext, Connection, EndpointId, TransportBudget, TransportErrorKind,
    local::{self, LocalAddress, LocalListener},
};
use std::time::{Duration, SystemTime};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let address = LocalAddress(format!("mutsuki-link-sidecar-{unique}"));
    let budget = TransportBudget {
        idle_timeout: None,
        ..TransportBudget::default()
    };
    let listener = LocalListener::bind(&address, EndpointId::from_bytes([2; 16]), budget)?;
    let context = ConnectContext::default();
    let (server, client) = tokio::join!(
        listener.accept(EndpointId::from_bytes([1; 16])),
        local::connect(
            &address,
            EndpointId::from_bytes([1; 16]),
            EndpointId::from_bytes([2; 16]),
            budget,
            &context,
        )
    );
    let (mut server, mut client) = (server?, client?);
    client.try_send_control(b"sidecar-health")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        match server.try_receive() {
            Ok(Some(message)) => {
                println!(
                    "local sidecar received {} bytes with peer credentials: {}",
                    message.len(),
                    server.peer_credentials().is_some()
                );
                break;
            }
            Err(error) if error.kind == TransportErrorKind::WouldBlock => {
                if tokio::time::Instant::now() >= deadline {
                    return Err("sidecar round trip timed out".into());
                }
                tokio::task::yield_now().await;
            }
            result => return Err(format!("sidecar receive failed: {result:?}").into()),
        }
    }
    client.close_write()?;
    Ok(())
}
