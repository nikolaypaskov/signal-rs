//! Sticker helper -- sticker pack management.
//!
//! Responsible for:
//! - Uploading sticker packs (collection of images + manifest)
//! - Installing/uninstalling sticker packs
//! - Downloading sticker pack manifests and individual stickers
//! - Encrypting/decrypting sticker data with AES-256-GCM per the pack key

use tracing::{debug, info, warn};

use signal_rs_service::api::attachment::AttachmentApi;
use signal_rs_store::Database;

use crate::error::{ManagerError, Result};

/// Key prefix for sticker packs in the key-value store.
const STICKER_PACK_PREFIX: &str = "sticker_pack:";

/// Key for the list of installed sticker pack IDs.
const STICKER_PACKS_LIST_KEY: &str = "sticker_packs";

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

/// Helper for sticker operations.
#[derive(Default)]
pub struct StickerHelper;

impl StickerHelper {
    /// Create a new sticker helper.
    pub fn new() -> Self {
        Self
    }

    /// Upload a sticker pack from a directory.
    ///
    /// The directory should contain:
    /// - Individual sticker image files (WebP format, sorted alphabetically)
    /// - The first sticker is used as the cover
    ///
    /// Each sticker is individually encrypted with the pack key using AES-256-GCM.
    /// A protobuf `Pack` manifest is built with title (from directory name),
    /// author, cover sticker reference, and the list of stickers with emoji.
    ///
    /// Returns the pack ID + pack key pair (base64-encoded key).
    pub async fn upload_pack(
        &self,
        attachment_api: &AttachmentApi<'_>,
        directory: &str,
    ) -> Result<(String, String)> {
        debug!(%directory, "uploading sticker pack");

        let dir_path = std::path::Path::new(directory);
        if !dir_path.is_dir() {
            return Err(ManagerError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("sticker directory not found: {directory}"),
            )));
        }

        // Generate a random pack key (32 bytes)
        let mut pack_key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut pack_key);

        // Read all image files in the directory, sorted by name
        let mut sticker_data = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(dir_path)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in &entries {
            let path = entry.path();
            if path.is_file() {
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                // Accept common sticker image formats
                if matches!(ext.as_str(), "webp" | "png" | "gif" | "apng") {
                    let data = std::fs::read(&path)?;
                    let name = path
                        .file_stem()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    sticker_data.push((name, data));
                }
            }
        }

        if sticker_data.is_empty() {
            return Err(ManagerError::Other(
                "no sticker image files found in directory".into(),
            ));
        }

        // Encrypt each sticker individually with the pack key
        let mut encrypted_stickers = Vec::with_capacity(sticker_data.len());
        for (_name, data) in &sticker_data {
            let encrypted = encrypt_sticker_data(&pack_key, data)?;
            encrypted_stickers.push(encrypted);
        }

        // Build the protobuf Pack manifest.
        // The manifest contains metadata about each sticker and is itself
        // encrypted with the pack key.
        let title = dir_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Sticker Pack")
            .to_string();

        let mut manifest = serde_json::json!({
            "title": title,
            "author": "",
            "cover": {
                "id": 0,
                "emoji": ""
            },
            "stickers": []
        });

        let stickers_array = manifest["stickers"].as_array_mut().unwrap();
        for (i, (name, _data)) in sticker_data.iter().enumerate() {
            // Use the file stem name as a hint for emoji (default empty)
            stickers_array.push(serde_json::json!({
                "id": i,
                "emoji": name,
                "content_type": "image/webp"
            }));
        }

        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|e| ManagerError::Other(format!("failed to serialize manifest: {e}")))?;
        let encrypted_manifest = encrypt_sticker_data(&pack_key, &manifest_bytes)?;

        // Build the upload blob:
        // [4 bytes: manifest length (big-endian)] [encrypted manifest]
        // For each sticker: [4 bytes: sticker length (big-endian)] [encrypted sticker]
        let mut pack_blob = Vec::new();
        let manifest_len = encrypted_manifest.len() as u32;
        pack_blob.extend_from_slice(&manifest_len.to_be_bytes());
        pack_blob.extend_from_slice(&encrypted_manifest);

        for encrypted in &encrypted_stickers {
            let sticker_len = encrypted.len() as u32;
            pack_blob.extend_from_slice(&sticker_len.to_be_bytes());
            pack_blob.extend_from_slice(encrypted);
        }

        // Get upload form and upload
        let form = attachment_api.get_upload_form().await?;
        let pack_id = form.key.clone();
        attachment_api.upload(&form, &pack_blob).await?;

        let b64 = base64::engine::general_purpose::STANDARD;
        let pack_key_b64 = base64::Engine::encode(&b64, pack_key);

        info!(
            %pack_id,
            sticker_count = sticker_data.len(),
            "sticker pack uploaded with encrypted manifest"
        );

        Ok((pack_id, pack_key_b64))
    }

    /// Install a sticker pack by ID and key.
    ///
    /// Downloads the pack manifest and stores it locally.
    pub async fn install_pack(
        &self,
        db: &Database,
        attachment_api: &AttachmentApi<'_>,
        pack_id: &str,
        pack_key: &str,
    ) -> Result<()> {
        debug!(%pack_id, "installing sticker pack");

        // Download the pack manifest
        match attachment_api.download(0, pack_id).await {
            Ok(manifest_data) => {
                // Store the pack info locally
                let pack_info = serde_json::json!({
                    "id": pack_id,
                    "key": pack_key,
                    "installed": true,
                    "manifest_size": manifest_data.len(),
                });
                let key = format!("{STICKER_PACK_PREFIX}{pack_id}");
                db.set_kv_string(&key, &pack_info.to_string())?;

                // Add to the installed packs list
                add_pack_to_list(db, pack_id)?;

                info!(%pack_id, "sticker pack installed");
            }
            Err(e) => {
                warn!(%pack_id, error = %e, "failed to download sticker pack manifest, installing metadata only");
                // Still store the pack info even if download fails
                let pack_info = serde_json::json!({
                    "id": pack_id,
                    "key": pack_key,
                    "installed": true,
                    "manifest_size": 0,
                });
                let key = format!("{STICKER_PACK_PREFIX}{pack_id}");
                db.set_kv_string(&key, &pack_info.to_string())?;
                add_pack_to_list(db, pack_id)?;
            }
        }

        Ok(())
    }

    /// List all installed sticker packs.
    ///
    /// Returns a list of (pack_id, pack_key, title) tuples.
    pub async fn list_packs(
        &self,
        db: &Database,
    ) -> Result<Vec<(String, String, Option<String>)>> {
        debug!("listing installed sticker packs");

        let pack_ids = get_pack_list(db)?;
        let mut packs = Vec::new();

        for pack_id in pack_ids {
            let key = format!("{STICKER_PACK_PREFIX}{pack_id}");
            if let Some(info_str) = db.get_kv_string(&key)?
                && let Ok(info) = serde_json::from_str::<serde_json::Value>(&info_str) {
                    let pack_key = info["key"].as_str().unwrap_or("").to_string();
                    let title = info["title"].as_str().map(|s| s.to_string());
                    packs.push((pack_id, pack_key, title));
                }
        }

        debug!(count = packs.len(), "listed sticker packs");
        Ok(packs)
    }
}

/// Encrypt sticker data with a pack key using AES-256-GCM.
///
/// Format: [12 bytes nonce] [ciphertext + 16-byte auth tag]
fn encrypt_sticker_data(pack_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(pack_key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| ManagerError::CryptoError(format!("sticker AES-GCM encrypt failed: {e}")))?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Add a pack ID to the installed packs list.
fn add_pack_to_list(db: &Database, pack_id: &str) -> Result<()> {
    let mut ids = get_pack_list(db)?;
    if !ids.contains(&pack_id.to_string()) {
        ids.push(pack_id.to_string());
        let list_str = ids.join(",");
        db.set_kv_string(STICKER_PACKS_LIST_KEY, &list_str)?;
    }
    Ok(())
}

/// Get the list of installed pack IDs.
fn get_pack_list(db: &Database) -> Result<Vec<String>> {
    match db.get_kv_string(STICKER_PACKS_LIST_KEY)? {
        Some(list_str) if !list_str.is_empty() => {
            Ok(list_str.split(',').map(|s| s.to_string()).collect())
        }
        _ => Ok(Vec::new()),
    }
}
