//! Attachment helper -- upload, download, and encryption.
//!
//! Responsible for:
//! - Reading attachment files from disk
//! - Encrypting attachments (AES-256-CBC + HMAC-SHA256)
//! - Uploading to the CDN via presigned URLs
//! - Downloading and decrypting received attachments
//! - Validating attachment sizes and types

use std::path::Path;

use tracing::{debug, info};

use signal_rs_service::api::attachment::AttachmentApi;
use signal_rs_service::attachment::{self, AttachmentKey};
use signal_rs_service::content::AttachmentInfo;

use crate::error::{ManagerError, Result};

/// Maximum attachment size (100 MB).
pub const MAX_ATTACHMENT_SIZE: u64 = 100 * 1024 * 1024;

/// Helper for attachment operations.
#[derive(Default)]
pub struct AttachmentHelper;

impl AttachmentHelper {
    /// Create a new attachment helper.
    pub fn new() -> Self {
        Self
    }

    /// Upload a file from the given path as an attachment.
    ///
    /// Returns the attachment pointer data needed for the message protobuf.
    pub async fn upload_attachment(
        &self,
        api: &AttachmentApi<'_>,
        file_path: &str,
    ) -> Result<AttachmentInfo> {
        debug!(file_path, "uploading attachment");

        // Validate first
        self.validate_attachment(file_path)?;

        // Read the file
        let data = tokio::fs::read(file_path).await?;
        let plaintext_len = data.len();

        // Generate a random 64-byte attachment key (32 bytes AES key + 32 bytes HMAC key)
        let attachment_key = AttachmentKey::generate();

        // Encrypt with AES-256-CBC + HMAC-SHA256
        let (encrypted_data, digest) = attachment::encrypt_attachment(&attachment_key, &data)?;

        // Get an upload form from the server
        let form = api.get_upload_form().await?;
        let cdn_key = form.key.clone();
        let cdn_number = form.cdn;

        // Upload the data
        api.upload(&form, &encrypted_data).await?;

        info!(
            file_path,
            cdn_key = %cdn_key,
            cdn_number,
            size = plaintext_len,
            "attachment uploaded"
        );

        // Guess content type from file extension
        let content_type = Path::new(file_path)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| match ext.to_lowercase().as_str() {
                "jpg" | "jpeg" => "image/jpeg",
                "png" => "image/png",
                "gif" => "image/gif",
                "webp" => "image/webp",
                "mp4" => "video/mp4",
                "mov" => "video/quicktime",
                "pdf" => "application/pdf",
                "txt" => "text/plain",
                "mp3" => "audio/mpeg",
                "ogg" => "audio/ogg",
                "wav" => "audio/wav",
                "m4a" => "audio/mp4",
                "aac" => "audio/aac",
                _ => "application/octet-stream",
            })
            .unwrap_or("application/octet-stream")
            .to_string();

        let file_name = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());

        Ok(AttachmentInfo {
            cdn_number,
            cdn_key,
            content_type,
            key: attachment_key.combined.to_vec(),
            size: plaintext_len as u64,
            file_name,
            digest: digest.to_vec(),
            width: 0,
            height: 0,
            caption: None,
        })
    }

    /// Download and decrypt an attachment.
    ///
    /// Returns the decrypted attachment bytes.
    pub async fn download_attachment(
        &self,
        api: &AttachmentApi<'_>,
        cdn_number: u32,
        cdn_key: &str,
        encryption_key: &[u8],
    ) -> Result<Vec<u8>> {
        debug!(cdn_number, cdn_key, "downloading attachment");

        let encrypted_data = api.download(cdn_number, cdn_key).await?;

        // Decrypt with AES-256-CBC + HMAC-SHA256
        let key = AttachmentKey::from_bytes(encryption_key)?;
        let decrypted_data = attachment::decrypt_attachment(&key, &encrypted_data, None)?;

        info!(
            cdn_key,
            cdn_number,
            size = decrypted_data.len(),
            "attachment downloaded"
        );

        Ok(decrypted_data)
    }

    /// Validate that a file can be sent as an attachment.
    pub fn validate_attachment(&self, file_path: &str) -> Result<()> {
        let path = Path::new(file_path);

        if !path.exists() {
            return Err(ManagerError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("attachment file not found: {file_path}"),
            )));
        }

        let metadata = std::fs::metadata(path)?;

        if !metadata.is_file() {
            return Err(ManagerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("attachment path is not a file: {file_path}"),
            )));
        }

        let size = metadata.len();
        if size > MAX_ATTACHMENT_SIZE {
            return Err(ManagerError::AttachmentTooLarge {
                size,
                max: MAX_ATTACHMENT_SIZE,
            });
        }

        if size == 0 {
            return Err(ManagerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("attachment file is empty: {file_path}"),
            )));
        }

        debug!(file_path, size, "attachment validated");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_nonexistent_file_fails() {
        let helper = AttachmentHelper::new();
        let result = helper.validate_attachment("/tmp/signal_rs_test_nonexistent_file_xyz.dat");
        assert!(result.is_err());
    }

    #[test]
    fn validate_existing_file_succeeds() {
        let helper = AttachmentHelper::new();
        // Create a temporary file with some content
        let dir = std::env::temp_dir().join("signal_rs_test_attachment");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test_file.txt");
        std::fs::write(&file_path, b"test attachment data").unwrap();

        let result = helper.validate_attachment(file_path.to_str().unwrap());
        assert!(result.is_ok());

        // Clean up
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn validate_empty_file_fails() {
        let helper = AttachmentHelper::new();
        let dir = std::env::temp_dir().join("signal_rs_test_attachment_empty");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("empty.txt");
        std::fs::write(&file_path, b"").unwrap();

        let result = helper.validate_attachment(file_path.to_str().unwrap());
        assert!(result.is_err());

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn validate_directory_fails() {
        let helper = AttachmentHelper::new();
        let dir = std::env::temp_dir().join("signal_rs_test_attachment_dir");
        std::fs::create_dir_all(&dir).unwrap();

        let result = helper.validate_attachment(dir.to_str().unwrap());
        assert!(result.is_err());

        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn max_attachment_size_is_100mb() {
        assert_eq!(MAX_ATTACHMENT_SIZE, 100 * 1024 * 1024);
    }
}
