//! Cloud-native blob storage for sealed key shares.
//!
//! Supports GCP Cloud Storage, AWS S3, Azure Blob Storage, plain HTTPS,
//! and local files. Auth uses the VM's native cloud identity (service
//! account, instance profile, managed identity) — no credentials needed.

use std::collections::BTreeMap;
use std::error::Error;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::SystemTime;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

type HmacSha256 = Hmac<Sha256>;

const MAX_BLOB_SIZE: usize = 1024 * 1024; // 1 MB
const METADATA_TIMEOUT_SECS: u64 = 5;
const TRANSFER_TIMEOUT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// URL classification
// ---------------------------------------------------------------------------

enum StorageUrl {
    File(String),
    Gcs { bucket: String, object: String },
    S3 { bucket: String, key: String },
    /// Azure Blob or plain HTTPS — distinguished at request time by hostname.
    Https(String),
}

fn classify_url(url: &str) -> Result<StorageUrl, Box<dyn Error>> {
    if url.starts_with("file://") {
        Ok(StorageUrl::File(url[7..].to_string()))
    } else if url.starts_with("gs://") {
        let path = &url[5..];
        let (bucket, object) = path
            .split_once('/')
            .ok_or("gs:// URL must be gs://bucket/object")?;
        if bucket.is_empty() || object.is_empty() {
            return Err("gs:// bucket and object must be non-empty".into());
        }
        Ok(StorageUrl::Gcs {
            bucket: bucket.to_string(),
            object: object.to_string(),
        })
    } else if url.starts_with("s3://") {
        let path = &url[5..];
        let (bucket, key) = path
            .split_once('/')
            .ok_or("s3:// URL must be s3://bucket/key")?;
        if bucket.is_empty() || key.is_empty() {
            return Err("s3:// bucket and key must be non-empty".into());
        }
        Ok(StorageUrl::S3 {
            bucket: bucket.to_string(),
            key: key.to_string(),
        })
    } else if url.starts_with("https://") {
        Ok(StorageUrl::Https(url.to_string()))
    } else {
        Err(format!("unsupported URL scheme: {url}").into())
    }
}

/// Returns true if the URL scheme is acceptable for --upload-url / SEALED_KEY_URL.
pub fn is_valid_storage_url(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("gs://")
        || url.starts_with("s3://")
        || url.starts_with("file://")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub async fn download_blob(url: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let parsed = classify_url(url)?;
    match parsed {
        StorageUrl::File(path) => file_download(&path).await,
        StorageUrl::Gcs { bucket, object } => gcs_download(&bucket, &object).await,
        StorageUrl::S3 { bucket, key } => s3_download(&bucket, &key).await,
        StorageUrl::Https(url) => https_download(&url).await,
    }
}

pub async fn upload_blob(url: &str, data: Vec<u8>) -> Result<(), Box<dyn Error>> {
    let parsed = classify_url(url)?;
    match parsed {
        StorageUrl::File(path) => file_upload(&path, &data).await,
        StorageUrl::Gcs { bucket, object } => gcs_upload(&bucket, &object, &data).await,
        StorageUrl::S3 { bucket, key } => s3_upload(&bucket, &key, &data).await,
        StorageUrl::Https(url) => https_upload(&url, &data).await,
    }
}

/// Strips query params from a URL for safe logging.
pub fn display_url(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

// ---------------------------------------------------------------------------
// File
// ---------------------------------------------------------------------------

async fn file_download(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    warn!("using file:// URL for sealed blob — not recommended for production");
    let bytes = tokio::fs::read(path).await?;
    if bytes.len() > MAX_BLOB_SIZE {
        return Err("sealed blob too large (>1MB)".into());
    }
    Ok(bytes)
}

async fn file_upload(path: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
    warn!("using file:// URL for upload — not recommended for production");
    tokio::fs::write(path, data).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// GCP Cloud Storage
// ---------------------------------------------------------------------------

async fn gcp_access_token() -> Result<String, Box<dyn Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(METADATA_TIMEOUT_SECS))
        .build()?;
    let resp = client
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
        .header("Metadata-Flavor", "Google")
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!(
            "GCP metadata token request failed: HTTP {}",
            resp.status()
        )
        .into());
    }

    let body: serde_json::Value = resp.json().await?;
    body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "no access_token in GCP metadata response".into())
}

async fn gcs_download(bucket: &str, object: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    info!(bucket, object, "gcs: downloading blob");
    let token = gcp_access_token().await?;

    // URL-encode the object name for the JSON API path
    let encoded = object.replace('/', "%2F");
    let url = format!(
        "https://storage.googleapis.com/storage/v1/b/{bucket}/o/{encoded}?alt=media"
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(TRANSFER_TIMEOUT_SECS))
        .build()?;

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!("GCS download failed: HTTP {}", resp.status()).into());
    }

    if let Some(len) = resp.content_length() {
        if len > MAX_BLOB_SIZE as u64 {
            return Err("sealed blob too large (Content-Length > 1MB)".into());
        }
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_BLOB_SIZE {
        return Err("sealed blob too large (>1MB)".into());
    }
    info!(size = bytes.len(), "gcs: download complete");
    Ok(bytes.to_vec())
}

async fn gcs_upload(bucket: &str, object: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
    info!(bucket, object, size = data.len(), "gcs: uploading blob");
    let token = gcp_access_token().await?;

    let encoded = object.replace('/', "%2F");
    let url = format!(
        "https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o?uploadType=media&name={encoded}"
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/octet-stream")
        .body(data.to_vec())
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("GCS upload failed: HTTP {status}: {body}").into());
    }

    info!("gcs: upload complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Azure Blob Storage (managed identity)
// ---------------------------------------------------------------------------

/// Returns true if this looks like an Azure Blob Storage URL.
fn is_azure_blob_url(url: &str) -> bool {
    url.contains(".blob.core.windows.net/")
}

/// Returns true if the URL contains a SAS token (skip managed identity auth).
fn has_sas_token(url: &str) -> bool {
    url.contains("sig=") && url.contains("se=")
}

async fn azure_access_token() -> Result<String, Box<dyn Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(METADATA_TIMEOUT_SECS))
        .build()?;
    let resp = client
        .get("http://169.254.169.254/metadata/identity/oauth2/token")
        .query(&[
            ("api-version", "2018-02-01"),
            ("resource", "https://storage.azure.com/"),
        ])
        .header("Metadata", "true")
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!(
            "Azure managed identity token request failed: HTTP {}",
            resp.status()
        )
        .into());
    }

    let body: serde_json::Value = resp.json().await?;
    body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "no access_token in Azure identity response".into())
}

async fn azure_download(url: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    info!(url = display_url(url), "azure: downloading blob");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(TRANSFER_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut req = client.get(url).header("x-ms-version", "2020-10-02");

    if !has_sas_token(url) {
        let token = azure_access_token().await?;
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Err(format!("Azure Blob download failed: HTTP {}", resp.status()).into());
    }

    if let Some(len) = resp.content_length() {
        if len > MAX_BLOB_SIZE as u64 {
            return Err("sealed blob too large (Content-Length > 1MB)".into());
        }
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_BLOB_SIZE {
        return Err("sealed blob too large (>1MB)".into());
    }
    info!(size = bytes.len(), "azure: download complete");
    Ok(bytes.to_vec())
}

async fn azure_upload(url: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
    info!(url = display_url(url), size = data.len(), "azure: uploading blob");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut req = client
        .put(url)
        .header("x-ms-version", "2020-10-02")
        .header("x-ms-blob-type", "BlockBlob")
        .header("Content-Type", "application/octet-stream")
        .body(data.to_vec());

    if !has_sas_token(url) {
        let token = azure_access_token().await?;
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Azure Blob upload failed: HTTP {status}: {body}").into());
    }

    info!("azure: upload complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// AWS S3 (instance profile + SigV4)
// ---------------------------------------------------------------------------

struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

/// Fetch temporary credentials and region from EC2 instance metadata (IMDSv2).
async fn aws_get_credentials_and_region(
) -> Result<(AwsCredentials, String), Box<dyn Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(METADATA_TIMEOUT_SECS))
        .build()?;

    // IMDSv2: get session token
    let token_resp = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "300")
        .send()
        .await?;
    let imds_token = token_resp.text().await?;

    // Get IAM role name
    let role_resp = client
        .get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        .header("X-aws-ec2-metadata-token", &imds_token)
        .send()
        .await?;
    let role_name = role_resp.text().await?;
    let role_name = role_name.trim();

    // Get credentials
    let creds_resp = client
        .get(format!(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
        ))
        .header("X-aws-ec2-metadata-token", &imds_token)
        .send()
        .await?;
    let creds: serde_json::Value = creds_resp.json().await?;

    // Get region
    let region_resp = client
        .get("http://169.254.169.254/latest/meta-data/placement/region")
        .header("X-aws-ec2-metadata-token", &imds_token)
        .send()
        .await?;
    let region = region_resp.text().await?.trim().to_string();

    Ok((
        AwsCredentials {
            access_key_id: creds["AccessKeyId"]
                .as_str()
                .ok_or("no AccessKeyId in IMDS credentials")?
                .to_string(),
            secret_access_key: creds["SecretAccessKey"]
                .as_str()
                .ok_or("no SecretAccessKey in IMDS credentials")?
                .to_string(),
            session_token: creds["Token"].as_str().map(|s| s.to_string()),
        },
        region,
    ))
}

async fn s3_download(bucket: &str, key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    info!(bucket, key, "s3: downloading blob");
    let (creds, region) = aws_get_credentials_and_region().await?;
    let host = format!("{bucket}.s3.{region}.amazonaws.com");
    let url = format!("https://{host}/{key}");

    let headers = sigv4_headers("GET", &host, &format!("/{key}"), "", &region, &creds, b"");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(TRANSFER_TIMEOUT_SECS))
        .build()?;

    let mut req = client.get(&url);
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Err(format!("S3 download failed: HTTP {}", resp.status()).into());
    }

    if let Some(len) = resp.content_length() {
        if len > MAX_BLOB_SIZE as u64 {
            return Err("sealed blob too large (Content-Length > 1MB)".into());
        }
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_BLOB_SIZE {
        return Err("sealed blob too large (>1MB)".into());
    }
    info!(size = bytes.len(), "s3: download complete");
    Ok(bytes.to_vec())
}

async fn s3_upload(bucket: &str, key: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
    info!(bucket, key, size = data.len(), "s3: uploading blob");
    let (creds, region) = aws_get_credentials_and_region().await?;
    let host = format!("{bucket}.s3.{region}.amazonaws.com");
    let url = format!("https://{host}/{key}");

    let headers = sigv4_headers("PUT", &host, &format!("/{key}"), "", &region, &creds, data);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut req = client
        .put(&url)
        .header("Content-Type", "application/octet-stream")
        .body(data.to_vec());
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("S3 upload failed: HTTP {status}: {body}").into());
    }

    info!("s3: upload complete");
    Ok(())
}

// -- AWS SigV4 signing --

fn sigv4_headers(
    method: &str,
    host: &str,
    canonical_uri: &str,
    canonical_querystring: &str,
    region: &str,
    creds: &AwsCredentials,
    payload: &[u8],
) -> BTreeMap<String, String> {
    let (date_stamp, amz_date) = utc_now();
    let payload_hash = sha256_hex(payload);

    // Build canonical headers (must be sorted by header name)
    let mut signed = BTreeMap::new();
    signed.insert("host".to_string(), host.to_string());
    signed.insert(
        "x-amz-content-sha256".to_string(),
        payload_hash.clone(),
    );
    signed.insert("x-amz-date".to_string(), amz_date.clone());
    if let Some(ref token) = creds.session_token {
        signed.insert("x-amz-security-token".to_string(), token.clone());
    }

    let signed_headers_str: String = signed.keys().cloned().collect::<Vec<_>>().join(";");

    let canonical_headers: String =
        signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers_str}\n{payload_hash}"
    );

    let credential_scope = format!("{date_stamp}/{region}/s3/aws4_request");

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    // Derive signing key
    let k_date = hmac_sha256(
        format!("AWS4{}", creds.secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers_str}, Signature={signature}",
        creds.access_key_id
    );

    let mut result = signed;
    result.insert("authorization".to_string(), authorization);
    result
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC can accept any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Returns (date_stamp "YYYYMMDD", amz_date "YYYYMMDDTHHMMSSZ").
fn utc_now() -> (String, String) {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs();

    let (year, month, day) = civil_from_days((secs / 86400) as i64);
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    let date_stamp = format!("{year:04}{month:02}{day:02}");
    let amz_date = format!("{date_stamp}T{hours:02}{minutes:02}{seconds:02}Z");
    (date_stamp, amz_date)
}

/// Howard Hinnant's civil_from_days algorithm.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

// ---------------------------------------------------------------------------
// Plain HTTPS (with SSRF protection + Azure managed identity auto-detect)
// ---------------------------------------------------------------------------

async fn https_download(url: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    // Detect Azure Blob Storage URLs and use managed identity auth
    if is_azure_blob_url(url) {
        return azure_download(url).await;
    }

    ssrf_check(url)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(TRANSFER_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(format!("HTTP download failed: HTTP {}", resp.status()).into());
    }
    if let Some(len) = resp.content_length() {
        if len > MAX_BLOB_SIZE as u64 {
            return Err("sealed blob too large (Content-Length > 1MB)".into());
        }
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_BLOB_SIZE {
        return Err("sealed blob too large (>1MB)".into());
    }
    Ok(bytes.to_vec())
}

async fn https_upload(url: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
    // Detect Azure Blob Storage URLs and use managed identity auth
    if is_azure_blob_url(url) {
        return azure_upload(url, data).await;
    }

    ssrf_check(url)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let resp = client
        .put(url)
        .header("Content-Type", "application/octet-stream")
        .body(data.to_vec())
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("HTTP upload failed: HTTP {status}: {body}").into());
    }
    Ok(())
}

// -- SSRF protection (for plain HTTPS URLs only) --

fn ssrf_check(url: &str) -> Result<(), Box<dyn Error>> {
    let authority = url
        .strip_prefix("https://")
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("");
    let host_for_resolve = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:443")
    };
    let addrs: Vec<SocketAddr> = host_for_resolve
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve host: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err("host resolved to no addresses".into());
    }
    for addr in &addrs {
        if is_non_global_ip(&addr.ip()) {
            return Err(format!(
                "URL resolved to non-public address {} — SSRF blocked",
                addr.ip()
            )
            .into());
        }
    }
    Ok(())
}

fn is_non_global_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // Shared address space (RFC 6598)
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || match v6.to_ipv4_mapped() {
                    Some(v4) => is_non_global_ip(&IpAddr::V4(v4)),
                    None => false,
                }
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_gcs() {
        match classify_url("gs://my-bucket/path/to/object.bin").unwrap() {
            StorageUrl::Gcs { bucket, object } => {
                assert_eq!(bucket, "my-bucket");
                assert_eq!(object, "path/to/object.bin");
            }
            _ => panic!("expected Gcs"),
        }
    }

    #[test]
    fn test_classify_s3() {
        match classify_url("s3://my-bucket/node-1-sealed.bin").unwrap() {
            StorageUrl::S3 { bucket, key } => {
                assert_eq!(bucket, "my-bucket");
                assert_eq!(key, "node-1-sealed.bin");
            }
            _ => panic!("expected S3"),
        }
    }

    #[test]
    fn test_classify_azure_blob_https() {
        match classify_url("https://account.blob.core.windows.net/container/blob.bin").unwrap() {
            StorageUrl::Https(url) => {
                assert!(is_azure_blob_url(&url));
            }
            _ => panic!("expected Https"),
        }
    }

    #[test]
    fn test_classify_plain_https() {
        match classify_url("https://example.com/blob.bin").unwrap() {
            StorageUrl::Https(url) => {
                assert!(!is_azure_blob_url(&url));
            }
            _ => panic!("expected Https"),
        }
    }

    #[test]
    fn test_classify_file() {
        match classify_url("file:///tmp/sealed.bin").unwrap() {
            StorageUrl::File(path) => assert_eq!(path, "/tmp/sealed.bin"),
            _ => panic!("expected File"),
        }
    }

    #[test]
    fn test_classify_invalid_scheme() {
        assert!(classify_url("ftp://bucket/key").is_err());
    }

    #[test]
    fn test_classify_empty_bucket() {
        assert!(classify_url("gs:///object").is_err());
        assert!(classify_url("s3:///key").is_err());
    }

    #[test]
    fn test_sas_token_detection() {
        assert!(has_sas_token("https://a.blob.core.windows.net/c/b?sig=abc&se=2025"));
        assert!(!has_sas_token("https://a.blob.core.windows.net/c/b"));
    }

    #[test]
    fn test_civil_from_days() {
        // 1970-01-01 = day 0
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2025-01-01 = day 20089
        assert_eq!(civil_from_days(20089), (2025, 1, 1));
    }

    #[test]
    fn test_display_url_strips_query() {
        assert_eq!(
            display_url("https://a.com/b?sig=secret&se=2025"),
            "https://a.com/b"
        );
        assert_eq!(display_url("gs://bucket/obj"), "gs://bucket/obj");
    }
}
