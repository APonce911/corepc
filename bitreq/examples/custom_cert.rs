//! This example demonstrates the client builder with custom DER certificate.
//! to run: cargo run --example custom_cert --features async-https-rustls or
//! cargo run --example custom_cert --features async-https-native-tls
#[cfg(not(any(feature = "async-https-rustls", feature = "async-https-native-tls")))]
fn main() {
    println!(
        "This example requires the 'async-https-rustls' or 'async-https-native-tls' features."
    );
}

#[cfg(any(feature = "async-https-rustls", feature = "async-https-native-tls"))]
fn main() -> Result<(), bitreq::Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("failed to build Tokio runtime");

    runtime.block_on(request_with_client())
}

#[cfg(any(feature = "async-https-rustls", feature = "async-https-native-tls"))]
async fn request_with_client() -> Result<(), bitreq::Error> {
    let url = "https://example.com";
    let cert_der = include_bytes!("../tests/test_cert.der");
    let client = bitreq::Client::builder().with_root_certificate(cert_der.as_slice())?.build()?;
    // OR
    // let cert_der: &[u8] = include_bytes!("../tests/test_cert.der");
    // let client = bitreq::Client::builder().with_root_certificate(cert_der)?.build()?;
    // OR
    // let cert_vec: Vec<u8> = include_bytes!("../tests/test_cert.der").to_vec();
    // let client = bitreq::Client::builder().with_root_certificate(cert_vec.as_slice())?.build()?;

    let response = client.send_async(bitreq::get(url)).await.unwrap();

    println!("Status: {}", response.status_code);
    println!("Body: {}", response.as_str()?);

    Ok(())
}
