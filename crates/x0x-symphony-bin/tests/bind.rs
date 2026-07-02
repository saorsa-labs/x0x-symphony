use std::error::Error;

use x0x_symphony_bin::api::validate_loopback_bind;

#[test]
fn rejects_unspecified_bind_address() {
    assert!(validate_loopback_bind("0.0.0.0:0").is_err());
}

#[test]
fn accepts_loopback_bind_address() -> Result<(), Box<dyn Error>> {
    let addr = validate_loopback_bind("127.0.0.1:0")?;
    assert!(addr.ip().is_loopback());
    assert_eq!(addr.port(), 0);
    Ok(())
}
