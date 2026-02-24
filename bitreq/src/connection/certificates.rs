#[cfg(feature = "rustls")]
use std::sync::Arc;
#[cfg(all(feature = "native-tls", not(feature = "rustls"), feature = "tokio-native-tls"))]
use std::sync::{Arc, Mutex};

#[cfg(all(feature = "native-tls", not(feature = "rustls")))]
use native_tls::{Certificate, TlsConnector, TlsConnectorBuilder};
#[cfg(feature = "rustls")]
use rustls::RootCertStore;
#[cfg(feature = "rustls-webpki")]
use webpki_roots::TLS_SERVER_ROOTS;

use crate::Error;

#[derive(Clone)]
#[cfg(feature = "rustls")]
pub(crate) struct Certificates {
    pub(crate) inner: Arc<RootCertStore>,
}

#[derive(Clone)]
#[cfg(all(feature = "native-tls", not(feature = "rustls"), feature = "tokio-native-tls"))]
pub(crate) struct Certificates {
    pub(crate) inner: CertificatesInner,
}

#[derive(Clone)]
#[cfg(all(feature = "native-tls", not(feature = "rustls"), feature = "tokio-native-tls"))]
pub(crate) enum CertificatesInner {
    Builder(Arc<Mutex<TlsConnectorBuilder>>),
    Built(TlsConnector),
}

impl Certificates {
    #[cfg(feature = "rustls")]
    pub(crate) fn new(cert_der: Option<Vec<u8>>) -> Result<Self, Error> {
        let certificates = Self { inner: Arc::new(RootCertStore::empty()) };

        if let Some(cert_der) = cert_der {
            certificates.append_certificate(cert_der)
        } else {
            Ok(certificates)
        }
    }

    #[cfg(all(feature = "native-tls", not(feature = "rustls"), feature = "tokio-native-tls"))]
    pub(crate) fn new(cert_der: Option<Vec<u8>>) -> Result<Self, Error> {
        let builder = TlsConnector::builder();
        let inner = CertificatesInner::Builder(Arc::new(Mutex::new(builder)));
        let certificates = Self { inner: inner };

        if let Some(cert_der) = cert_der {
            certificates.append_certificate(cert_der)
        } else {
            Ok(certificates)
        }
    }

    #[cfg(feature = "rustls")]
    pub(crate) fn append_certificate(mut self, cert_der: Vec<u8>) -> Result<Self, Error> {
        let certificates = Arc::make_mut(&mut self.inner);
        certificates.add(&rustls::Certificate(cert_der)).map_err(Error::RustlsAppendCert)?;

        Ok(self)
    }

    #[cfg(all(feature = "native-tls", not(feature = "rustls"), feature = "tokio-native-tls"))]
    pub(crate) fn append_certificate(mut self, cert_der: Vec<u8>) -> Result<Self, Error> {
        let new_inner = match self.inner {
            CertificatesInner::Builder(builder_mutex) => {
                let certificate = Certificate::from_der(&cert_der)?;

                {
                    let mut builder_guard = builder_mutex.lock().unwrap();
                    builder_guard.add_root_certificate(certificate);
                }

                CertificatesInner::Builder(builder_mutex)
            }
            CertificatesInner::Built(_) => return Err(Error::NativeTlsAppendCert),
        };

        self.inner = new_inner;
        Ok(self)
    }

    #[cfg(all(feature = "native-tls", not(feature = "rustls"), feature = "tokio-native-tls"))]
    pub(crate) fn build(mut self) -> Result<Self, Error> {
        let new_inner = match self.inner {
            CertificatesInner::Builder(builder_mutex) => {
                let mut builder_guard = builder_mutex.lock().unwrap();
                let connector = builder_guard.build()?;

                CertificatesInner::Built(connector)
            }
            CertificatesInner::Built(_) => return Ok(self),
        };

        self.inner = new_inner;
        Ok(self)
    }

    #[cfg(feature = "rustls")]
    pub(crate) fn with_root_certificates(mut self) -> Self {
        let root_certificates = Arc::make_mut(&mut self.inner);

        // Try to load native certs
        #[cfg(feature = "https-rustls-probe")]
        if let Ok(os_roots) = rustls_native_certs::load_native_certs() {
            for root_cert in os_roots {
                // Ignore erroneous OS certificates, there's nothing
                // to do differently in that situation anyways.
                let _ = root_certificates.add(&rustls::Certificate(root_cert.0));
            }
        }

        #[cfg(feature = "rustls-webpki")]
        {
            #[allow(deprecated)]
            // Need to use add_server_trust_anchors to compile with rustls 0.21.1
            root_certificates.add_server_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
        }
        self
    }
}
