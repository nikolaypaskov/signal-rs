//! Attachment upload/download API.
//!
//! Endpoints:
//! - GET  /v2/attachments/form/upload       -- get upload form (S3 presigned URL)
//! - GET  cdn{n}.signal.org/attachments/{id} -- download attachment from CDN
//! - GET  /v3/attachments/form/upload       -- get resumable upload form (v3)

use serde::Deserialize;
use tracing::debug;

use crate::error::Result;
use crate::net::http::HttpClient;

/// The upload form returned by the server for attachment uploads (v2).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentUploadForm {
    /// The CDN number where the attachment will be stored.
    pub cdn: u32,
    /// The unique attachment key.
    pub key: String,
    /// Additional form headers/fields for the upload.
    pub headers: std::collections::HashMap<String, String>,
    /// The upload URL.
    pub signed_upload_location: String,
}

/// The upload form returned for resumable uploads (v3).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentV3UploadForm {
    /// The CDN number.
    pub cdn: u32,
    /// The unique attachment key.
    pub key: String,
    /// Additional form headers/fields for the upload.
    pub headers: std::collections::HashMap<String, String>,
    /// The upload URL that supports resumable uploads.
    pub signed_upload_location: String,
}

/// API client for attachment endpoints.
pub struct AttachmentApi<'a> {
    /// The HTTP client.
    http: &'a HttpClient,
}

impl<'a> AttachmentApi<'a> {
    /// Create a new attachment API client.
    pub fn new(http: &'a HttpClient) -> Self {
        Self { http }
    }

    /// Get a presigned upload form for a new attachment (v2).
    ///
    /// GET /v2/attachments/form/upload
    ///
    /// Returns a presigned URL and headers for uploading the attachment
    /// to Signal's CDN. The upload is a single PUT request.
    pub async fn get_upload_form(&self) -> Result<AttachmentUploadForm> {
        debug!("requesting attachment upload form (v2)");
        self.http.get_json("/v2/attachments/form/upload").await
    }

    /// Get a resumable upload form for a new attachment (v3).
    ///
    /// GET /v3/attachments/form/upload
    ///
    /// Returns a URL that supports resumable uploads, which is more
    /// reliable for large attachments on poor network connections.
    pub async fn get_resumable_upload_form(&self) -> Result<AttachmentV3UploadForm> {
        debug!("requesting attachment upload form (v3 resumable)");
        self.http.get_json("/v3/attachments/form/upload").await
    }

    /// Upload attachment bytes to the CDN using the provided form.
    ///
    /// Uses a single PUT request to the presigned URL.
    /// The data should already be encrypted with the attachment key.
    pub async fn upload(&self, form: &AttachmentUploadForm, data: &[u8]) -> Result<()> {
        debug!(
            url = %form.signed_upload_location,
            size = data.len(),
            "uploading attachment"
        );
        self.http
            .put_bytes(&form.signed_upload_location, data, "application/octet-stream")
            .await
    }

    /// Download an attachment from the CDN.
    ///
    /// GET cdn{cdn_number}.signal.org/attachments/{key}
    ///
    /// Returns the raw encrypted attachment bytes. The caller is responsible
    /// for decrypting the data using the attachment key from the
    /// AttachmentPointer protobuf.
    pub async fn download(&self, cdn_number: u32, key: &str) -> Result<Vec<u8>> {
        let cdn_base = self.http.cdn_url(cdn_number);
        let url = format!("{cdn_base}/attachments/{key}");
        debug!(url = %url, "downloading attachment");
        let bytes = self.http.get_unauthenticated(&url).await?;
        Ok(bytes.to_vec())
    }

    /// Download an attachment from a specific CDN path.
    ///
    /// This handles cases where the CDN path is a full URL or a
    /// path that doesn't follow the standard /attachments/{key} pattern.
    pub async fn download_from_path(&self, cdn_number: u32, path: &str) -> Result<Vec<u8>> {
        let cdn_base = self.http.cdn_url(cdn_number);
        let url = if path.starts_with('/') {
            format!("{cdn_base}{path}")
        } else {
            format!("{cdn_base}/{path}")
        };
        debug!(url = %url, "downloading attachment from path");
        let bytes = self.http.get_unauthenticated(&url).await?;
        Ok(bytes.to_vec())
    }

    /// Upload a sticker pack to the CDN.
    ///
    /// Uses the provided form to upload packed sticker data.
    pub async fn upload_sticker_pack(
        &self,
        form: &AttachmentUploadForm,
        data: &[u8],
    ) -> Result<String> {
        debug!(
            url = %form.signed_upload_location,
            size = data.len(),
            "uploading sticker pack"
        );
        self.http
            .put_bytes(&form.signed_upload_location, data, "application/octet-stream")
            .await?;
        Ok(form.key.clone())
    }

    /// Copy an attachment from one CDN to another (server-side copy).
    ///
    /// This is used when forwarding messages or migrating attachments.
    /// If the server doesn't support copy, falls back to download + re-upload.
    pub async fn copy_attachment(
        &self,
        source_cdn: u32,
        source_key: &str,
    ) -> Result<AttachmentUploadForm> {
        debug!(
            source_cdn = source_cdn,
            source_key = source_key,
            "copying attachment (download + re-upload)"
        );

        // Download from source
        let data = self.download(source_cdn, source_key).await?;

        // Get a new upload form
        let form = self.get_upload_form().await?;

        // Upload to the new location
        self.upload(&form, &data).await?;

        Ok(form)
    }
}
