//! Pre-key helper -- key generation and server synchronization.
//!
//! Responsible for:
//! - Generating new batches of EC pre-keys
//! - Generating signed pre-keys
//! - Generating Kyber (post-quantum) pre-keys
//! - Uploading pre-keys to the server
//! - Checking pre-key counts and refreshing when low

use base64::Engine;
use tracing::{debug, info};

use signal_rs_protocol::{
    ServiceIdKind, generate_pre_keys, generate_signed_pre_key, generate_kyber_pre_key,
};
use signal_rs_protocol::stores::{IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SignedPreKeyStore};
use signal_rs_service::api::keys::{
    KeysApi, KyberPreKeyUploadItem, PreKeyUpload, PreKeyUploadItem, SignedPreKeyUploadItem,
};
use signal_rs_store::Database;

use crate::error::{ManagerError, Result};

/// The threshold below which we should generate and upload new pre-keys.
pub const PRE_KEY_MINIMUM_COUNT: u32 = 10;

/// The number of pre-keys to generate in each batch.
pub const PRE_KEY_BATCH_SIZE: u32 = 100;

/// Key in the key-value store for tracking the next pre-key ID.
const NEXT_PRE_KEY_ID_KEY: &str = "next_pre_key_id";

/// Key in the key-value store for tracking the next signed pre-key ID.
const NEXT_SIGNED_PRE_KEY_ID_KEY: &str = "next_signed_pre_key_id";

/// Key in the key-value store for tracking the next Kyber pre-key ID.
const NEXT_KYBER_PRE_KEY_ID_KEY: &str = "next_kyber_pre_key_id";

/// Helper for pre-key management.
#[derive(Default)]
pub struct PreKeyHelper;

impl PreKeyHelper {
    /// Create a new pre-key helper.
    pub fn new() -> Self {
        Self
    }

    /// Check if the server needs more pre-keys and upload if necessary.
    pub async fn refresh_pre_keys_if_needed(
        &self,
        db: &Database,
        keys_api: &KeysApi<'_>,
    ) -> Result<()> {
        debug!("checking pre-key count on server");

        let count = keys_api.get_pre_key_count(ServiceIdKind::Aci).await?;
        debug!(
            ec_count = count.count,
            kyber_count = count.pq_count,
            "server pre-key counts"
        );

        if count.count < PRE_KEY_MINIMUM_COUNT {
            info!(
                ec_count = count.count,
                threshold = PRE_KEY_MINIMUM_COUNT,
                "pre-key count below threshold, generating new batch"
            );
            self.generate_and_upload_pre_keys(db, keys_api).await?;
        } else {
            debug!("pre-key count is sufficient");
        }

        Ok(())
    }

    /// Generate and upload a fresh batch of pre-keys.
    pub async fn generate_and_upload_pre_keys(
        &self,
        db: &Database,
        keys_api: &KeysApi<'_>,
    ) -> Result<()> {
        debug!("generating and uploading pre-keys");

        let b64 = &base64::engine::general_purpose::STANDARD;

        // Get the identity key pair for signing
        let identity_key_pair = db.get_identity_key_pair()
            .map_err(|e| ManagerError::Other(format!("failed to get identity key pair: {e}")))?;

        // Determine the next pre-key ID
        let next_pre_key_id = get_next_id(db, NEXT_PRE_KEY_ID_KEY)?;
        let next_signed_id = get_next_id(db, NEXT_SIGNED_PRE_KEY_ID_KEY)?;
        let next_kyber_id = get_next_id(db, NEXT_KYBER_PRE_KEY_ID_KEY)?;

        // Generate EC pre-keys
        let pre_keys = generate_pre_keys(next_pre_key_id, PRE_KEY_BATCH_SIZE);

        // Save pre-keys to the local store
        for pk in &pre_keys {
            db.save_pre_key(pk.id, pk)
                .map_err(|e| ManagerError::Other(format!("failed to save pre-key: {e}")))?;
        }

        // Generate a new signed pre-key and save locally
        let signed_pre_key = generate_signed_pre_key(next_signed_id, &identity_key_pair);
        db.save_signed_pre_key(signed_pre_key.id, &signed_pre_key)
            .map_err(|e| ManagerError::Other(format!("failed to save signed pre-key: {e}")))?;

        // Generate a Kyber pre-key (last resort) and save locally
        let kyber_pre_key = generate_kyber_pre_key(next_kyber_id, &identity_key_pair, true);
        db.save_kyber_pre_key(kyber_pre_key.id, &kyber_pre_key)
            .map_err(|e| ManagerError::Other(format!("failed to save kyber pre-key: {e}")))?;

        // Build the upload payload
        let pre_key_upload_items: Vec<PreKeyUploadItem> = pre_keys
            .iter()
            .map(|pk| PreKeyUploadItem {
                key_id: pk.id.0,
                public_key: b64.encode(&pk.public_key),
            })
            .collect();

        let signed_pre_key_upload = SignedPreKeyUploadItem {
            key_id: signed_pre_key.id.0,
            public_key: b64.encode(&signed_pre_key.public_key),
            signature: b64.encode(&signed_pre_key.signature),
        };

        let kyber_upload = KyberPreKeyUploadItem {
            key_id: kyber_pre_key.id.0,
            public_key: b64.encode(&kyber_pre_key.key_pair_serialized[..1569]),
            signature: b64.encode(&kyber_pre_key.signature),
        };

        let upload = PreKeyUpload {
            pre_keys: pre_key_upload_items,
            signed_pre_key: signed_pre_key_upload,
            last_resort_kyber_pre_key: Some(kyber_upload),
            kyber_pre_keys: Vec::new(),
        };

        // Upload to the server
        keys_api.upload_pre_keys(&upload, ServiceIdKind::Aci).await?;

        // Update the next ID counters
        set_next_id(db, NEXT_PRE_KEY_ID_KEY, next_pre_key_id + PRE_KEY_BATCH_SIZE)?;
        set_next_id(db, NEXT_SIGNED_PRE_KEY_ID_KEY, next_signed_id + 1)?;
        set_next_id(db, NEXT_KYBER_PRE_KEY_ID_KEY, next_kyber_id + 1)?;

        info!(
            ec_count = PRE_KEY_BATCH_SIZE,
            signed_pre_key_id = next_signed_id,
            "pre-keys uploaded"
        );

        Ok(())
    }

    /// Rotate the signed pre-key.
    pub async fn rotate_signed_pre_key(
        &self,
        db: &Database,
        keys_api: &KeysApi<'_>,
    ) -> Result<()> {
        debug!("rotating signed pre-key");

        let b64 = &base64::engine::general_purpose::STANDARD;

        let identity_key_pair = db.get_identity_key_pair()
            .map_err(|e| ManagerError::Other(format!("failed to get identity key pair: {e}")))?;

        let next_signed_id = get_next_id(db, NEXT_SIGNED_PRE_KEY_ID_KEY)?;
        let signed_pre_key = generate_signed_pre_key(next_signed_id, &identity_key_pair);

        // Save the signed pre-key locally
        db.save_signed_pre_key(signed_pre_key.id, &signed_pre_key)
            .map_err(|e| ManagerError::Other(format!("failed to save signed pre-key: {e}")))?;

        // We need a full upload to rotate the signed pre-key.
        // Generate a minimal batch of EC pre-keys as well.
        let next_pre_key_id = get_next_id(db, NEXT_PRE_KEY_ID_KEY)?;
        let pre_keys = generate_pre_keys(next_pre_key_id, PRE_KEY_BATCH_SIZE);

        for pk in &pre_keys {
            db.save_pre_key(pk.id, pk)
                .map_err(|e| ManagerError::Other(format!("failed to save pre-key: {e}")))?;
        }

        let pre_key_upload_items: Vec<PreKeyUploadItem> = pre_keys
            .iter()
            .map(|pk| PreKeyUploadItem {
                key_id: pk.id.0,
                public_key: b64.encode(&pk.public_key),
            })
            .collect();

        let signed_pre_key_upload = SignedPreKeyUploadItem {
            key_id: signed_pre_key.id.0,
            public_key: b64.encode(&signed_pre_key.public_key),
            signature: b64.encode(&signed_pre_key.signature),
        };

        let upload = PreKeyUpload {
            pre_keys: pre_key_upload_items,
            signed_pre_key: signed_pre_key_upload,
            last_resort_kyber_pre_key: None,
            kyber_pre_keys: Vec::new(),
        };

        keys_api.upload_pre_keys(&upload, ServiceIdKind::Aci).await?;

        set_next_id(db, NEXT_SIGNED_PRE_KEY_ID_KEY, next_signed_id + 1)?;
        set_next_id(db, NEXT_PRE_KEY_ID_KEY, next_pre_key_id + PRE_KEY_BATCH_SIZE)?;

        info!(signed_pre_key_id = next_signed_id, "signed pre-key rotated");
        Ok(())
    }
}

/// Get the next ID counter from the key-value store.
fn get_next_id(db: &Database, key: &str) -> Result<u32> {
    match db.get_kv_string(key)? {
        Some(s) => s.parse::<u32>().map_err(|e| {
            ManagerError::Other(format!("invalid next ID value for {key}: {e}"))
        }),
        None => Ok(1),
    }
}

/// Set the next ID counter in the key-value store.
fn set_next_id(db: &Database, key: &str, value: u32) -> Result<()> {
    db.set_kv_string(key, &value.to_string())?;
    Ok(())
}
