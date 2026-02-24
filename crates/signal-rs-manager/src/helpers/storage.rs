//! Storage helper -- storage service synchronization.
//!
//! Responsible for:
//! - Reading and writing the storage manifest
//! - Syncing contact, group, and account records
//! - Handling storage key encryption/decryption
//! - Conflict resolution during sync

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use hmac::Mac;
use prost::Message;
use sha2::Sha256;
use tracing::{debug, info, warn};

use signal_rs_protos::{
    ManifestRecord, StorageItem, StorageItems, StorageManifest, StorageRecord, WriteOperation,
};
use signal_rs_service::api::storage::StorageApi;
use signal_rs_store::Database;
use signal_rs_store::database::account_keys;

use crate::error::{ManagerError, Result};

type HmacSha256 = hmac::Hmac<Sha256>;

/// Key for the current storage manifest version in the key-value store.
const STORAGE_MANIFEST_VERSION_KEY: &str = "storage_manifest_version";

/// Key for the Account Entropy Pool in the key-value store.
const ACCOUNT_ENTROPY_POOL_KEY: &str = "account_entropy_pool";

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

/// Derive the master key (SVR key) from the Account Entropy Pool.
///
/// Uses HKDF-SHA256 with the AEP string bytes as IKM, no salt,
/// and info "20240801_SIGNAL_SVR_MASTER_KEY".
/// See: libsignal/rust/account-keys/src/lib.rs `derive_svr_key()`
fn derive_master_key_from_aep(aep: &str) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, aep.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(b"20240801_SIGNAL_SVR_MASTER_KEY", &mut key)
        .map_err(|e| ManagerError::Other(format!("HKDF expand (AEP→master) failed: {e}")))?;
    Ok(key)
}

/// Derive the storage encryption key from the master key using HMAC-SHA256.
///
/// `storage_key = HMAC-SHA256(key=master_key, data="Storage Service Encryption")`
///
/// See: Signal-Android MasterKey.kt `deriveStorageServiceKey()`
fn derive_storage_key(master_key: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master_key)
        .map_err(|e| ManagerError::Other(format!("HMAC key error: {e}")))?;
    mac.update(b"Storage Service Encryption");
    let result = mac.finalize().into_bytes();
    Ok(result.into())
}

/// Derive a per-manifest encryption key from the storage key.
///
/// `manifest_key = HMAC-SHA256(key=storage_key, data="Manifest_{version}")`
///
/// See: Signal-Android StorageKey.kt `deriveManifestKey()`
fn derive_manifest_key(storage_key: &[u8; 32], version: u64) -> Result<[u8; 32]> {
    let label = format!("Manifest_{version}");
    let mut mac = <HmacSha256 as Mac>::new_from_slice(storage_key)
        .map_err(|e| ManagerError::Other(format!("HMAC key error: {e}")))?;
    mac.update(label.as_bytes());
    let result = mac.finalize().into_bytes();
    Ok(result.into())
}

/// Derive a per-item encryption key from the storage key.
///
/// `item_key = HMAC-SHA256(key=storage_key, data="Item_{base64(rawId)}")`
///
/// See: Signal-Android StorageKey.kt `deriveItemKey()`
fn derive_item_key(storage_key: &[u8; 32], raw_id: &[u8]) -> Result<[u8; 32]> {
    let b64_id = base64::engine::general_purpose::STANDARD.encode(raw_id);
    let label = format!("Item_{b64_id}");
    let mut mac = <HmacSha256 as Mac>::new_from_slice(storage_key)
        .map_err(|e| ManagerError::Other(format!("HMAC key error: {e}")))?;
    mac.update(label.as_bytes());
    let result = mac.finalize().into_bytes();
    Ok(result.into())
}

/// Derive a per-item encryption key from the record IKM (when present in manifest).
///
/// `item_key = HKDF-SHA256(ikm=record_ikm, salt=None, info="20240801_SIGNAL_STORAGE_SERVICE_ITEM_" || rawId)`
///
/// When the manifest contains a `record_ikm` field, this takes priority over
/// `derive_item_key()` for per-item key derivation.
///
/// See: Signal-Android RecordIkm.kt `deriveStorageItemKey()`
fn derive_item_key_from_record_ikm(record_ikm: &[u8], raw_id: &[u8]) -> Result<[u8; 32]> {
    let mut info = b"20240801_SIGNAL_STORAGE_SERVICE_ITEM_".to_vec();
    info.extend_from_slice(raw_id);

    let hkdf = Hkdf::<Sha256>::new(None, record_ikm);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|e| ManagerError::Other(format!("HKDF expand (recordIkm→item key) failed: {e}")))?;
    Ok(key)
}

/// Derive the per-item key, using record_ikm if available, else storage_key.
///
/// This mirrors the Signal-Android logic:
/// `val key = recordIkm?.deriveStorageItemKey(rawId) ?: storageKey.deriveItemKey(rawId)`
fn derive_effective_item_key(
    storage_key: &[u8; 32],
    record_ikm: Option<&[u8]>,
    raw_id: &[u8],
) -> Result<[u8; 32]> {
    if let Some(ikm) = record_ikm {
        derive_item_key_from_record_ikm(ikm, raw_id)
    } else {
        derive_item_key(storage_key, raw_id)
    }
}

/// Get the effective master key for storage operations.
///
/// If an Account Entropy Pool is stored, derives the master key from it.
/// Otherwise falls back to the stored master key blob.
fn get_effective_master_key(db: &Database) -> Result<[u8; 32]> {
    // Prefer AEP-derived master key (modern accounts)
    if let Some(aep) = db.get_kv_string(ACCOUNT_ENTROPY_POOL_KEY)?
        && !aep.is_empty()
    {
        debug!("deriving master key from Account Entropy Pool");
        return derive_master_key_from_aep(&aep);
    }

    // Fall back to stored master key (legacy or provisioned directly)
    let master_key_blob = db
        .get_kv_blob(account_keys::MASTER_KEY)?
        .ok_or_else(|| ManagerError::Other("master key not found".into()))?;

    if master_key_blob.len() != 32 {
        return Err(ManagerError::Other(format!(
            "master key has wrong length: {} (expected 32)",
            master_key_blob.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&master_key_blob);
    Ok(key)
}

/// Encrypt data using AES-256-GCM with a random nonce.
///
/// Returns `nonce || ciphertext` (12 bytes nonce prepended to the ciphertext).
fn encrypt_aes256gcm(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes: [u8; NONCE_SIZE] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| ManagerError::Other(format!("AES-256-GCM encryption failed: {e}")))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data encrypted with AES-256-GCM.
///
/// Expects `nonce || ciphertext` format (12-byte nonce prefix).
fn decrypt_aes256gcm(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_SIZE {
        return Err(ManagerError::Other(
            "encrypted data too short for AES-256-GCM nonce".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| ManagerError::Other(format!("AES-256-GCM decryption failed: {e}")))
}

/// Helper for storage service operations.
#[derive(Default)]
pub struct StorageHelper;

impl StorageHelper {
    /// Create a new storage helper.
    pub fn new() -> Self {
        Self
    }

    /// Perform a full storage sync (fetch manifest, compare, merge).
    ///
    /// This:
    /// 1. Fetches the latest manifest from the server
    /// 2. Compares it with the local version
    /// 3. Downloads any new or updated records
    /// 4. Merges them into the local store
    /// 5. Uploads any local changes
    pub async fn sync(
        &self,
        db: &Database,
        storage_api: &StorageApi<'_>,
    ) -> Result<()> {
        debug!("starting storage sync");

        let local_version = get_manifest_version(db)?;

        // Check if there's a newer manifest on the server
        let manifest_data = if local_version > 0 {
            match storage_api.get_manifest_if_different(local_version).await? {
                Some(data) => {
                    debug!(
                        local_version,
                        "newer manifest available, downloading"
                    );
                    data
                }
                None => {
                    debug!(local_version, "manifest is up to date");
                    return Ok(());
                }
            }
        } else {
            // First sync - download the full manifest
            debug!("first sync, downloading full manifest");
            storage_api.get_manifest().await?
        };

        // Derive storage key from master key (or AEP)
        let master_key = get_effective_master_key(db)?;
        debug!(
            master_key_prefix = %hex::encode(&master_key[..4]),
            "using master key for storage"
        );
        let storage_key = derive_storage_key(&master_key)?;
        debug!(
            storage_key_prefix = %hex::encode(&storage_key[..4]),
            "derived storage key"
        );

        // Decode the outer StorageManifest protobuf
        debug!(manifest_data_len = manifest_data.len(), "decoding StorageManifest protobuf");
        let storage_manifest = StorageManifest::decode(manifest_data.as_slice())
            .map_err(|e| ManagerError::Other(format!("failed to decode StorageManifest: {e}")))?;

        let server_version = storage_manifest.version;
        debug!(
            server_version,
            value_len = storage_manifest.value.len(),
            "parsed StorageManifest"
        );

        // Decrypt the manifest value using a version-specific key
        let manifest_record = if !storage_manifest.value.is_empty() {
            let manifest_key = derive_manifest_key(&storage_key, server_version)?;
            debug!(
                encrypted_value_len = storage_manifest.value.len(),
                manifest_key_prefix = %hex::encode(&manifest_key[..4]),
                "decrypting manifest value with version-specific key"
            );
            let decrypted = decrypt_aes256gcm(&manifest_key, &storage_manifest.value)?;
            ManifestRecord::decode(decrypted.as_slice())
                .map_err(|e| ManagerError::Other(format!("failed to decode ManifestRecord: {e}")))?
        } else {
            debug!("manifest has no encrypted value, nothing to sync");
            set_manifest_version(db, server_version)?;
            return Ok(());
        };

        // Extract record_ikm from manifest (if present, used for item key derivation)
        let record_ikm = if !manifest_record.record_ikm.is_empty() {
            debug!(
                record_ikm_len = manifest_record.record_ikm.len(),
                record_ikm_prefix = %hex::encode(&manifest_record.record_ikm[..4.min(manifest_record.record_ikm.len())]),
                "manifest contains record_ikm, will use HKDF for item keys"
            );
            Some(manifest_record.record_ikm.clone())
        } else {
            debug!("no record_ikm in manifest, using HMAC-based item keys");
            None
        };

        // Collect record keys that we need to download
        let identifiers = &manifest_record.identifiers;
        if identifiers.is_empty() {
            debug!("manifest contains no record identifiers");
            set_manifest_version(db, server_version)?;
            return Ok(());
        }

        // Gather all record keys to download
        let record_keys: Vec<Vec<u8>> = identifiers
            .iter()
            .filter(|id| !id.raw.is_empty())
            .map(|id| id.raw.clone())
            .collect();

        if record_keys.is_empty() {
            debug!("no record keys to download");
            set_manifest_version(db, server_version)?;
            return Ok(());
        }

        info!(
            count = record_keys.len(),
            server_version, "downloading storage records"
        );

        // Download records from the server
        let items_data = storage_api.read_records(&record_keys).await?;
        let storage_items = StorageItems::decode(items_data.as_slice())
            .map_err(|e| ManagerError::Other(format!("failed to decode StorageItems: {e}")))?;

        // Decrypt and merge each record
        let mut contacts_merged = 0u32;
        let mut groups_merged = 0u32;
        let mut account_merged = false;
        let mut skipped = 0u32;

        for item in &storage_items.items {
            let storage_id = item.key.clone();
            if item.value.is_empty() {
                debug!(id = %hex::encode(&storage_id), "skipping item with no/empty value (tombstone)");
                skipped += 1;
                continue;
            }
            let encrypted_value = &item.value;

            // Skip items too short to contain valid AES-GCM data (nonce + at least tag)
            if encrypted_value.len() < NONCE_SIZE + 16 {
                debug!(
                    id = %hex::encode(&storage_id),
                    len = encrypted_value.len(),
                    "skipping item too short for AES-256-GCM"
                );
                skipped += 1;
                continue;
            }

            // Derive per-item key: use record_ikm (HKDF) if available, else storage_key (HMAC)
            let item_key = match derive_effective_item_key(
                &storage_key,
                record_ikm.as_deref(),
                &storage_id,
            ) {
                Ok(k) => k,
                Err(e) => {
                    warn!("failed to derive item key: {e}");
                    skipped += 1;
                    continue;
                }
            };

            let decrypted = match decrypt_aes256gcm(&item_key, encrypted_value) {
                Ok(d) => d,
                Err(e) => {
                    warn!("failed to decrypt storage record: {e}");
                    skipped += 1;
                    continue;
                }
            };

            let record = match StorageRecord::decode(decrypted.as_slice()) {
                Ok(r) => r,
                Err(e) => {
                    warn!("failed to decode StorageRecord: {e}");
                    skipped += 1;
                    continue;
                }
            };

            match record.record {
                Some(signal_rs_protos::storage_record::Record::Contact(contact)) => {
                    merge_contact(db, &storage_id, &contact)?;
                    contacts_merged += 1;
                }
                Some(signal_rs_protos::storage_record::Record::GroupV2(group)) => {
                    merge_group_v2(db, &storage_id, &group)?;
                    groups_merged += 1;
                }
                Some(signal_rs_protos::storage_record::Record::Account(account)) => {
                    merge_account(db, &storage_id, &account)?;
                    account_merged = true;
                }
                Some(signal_rs_protos::storage_record::Record::GroupV1(group_v1)) => {
                    merge_group_v1(db, &storage_id, &group_v1)?;
                    debug!("merged group_v1 record from storage");
                }
                Some(signal_rs_protos::storage_record::Record::StoryDistributionList(sdl)) => {
                    merge_story_distribution_list(db, &storage_id, &sdl)?;
                    debug!("merged story_distribution_list record from storage");
                }
                Some(signal_rs_protos::storage_record::Record::StickerPack(sp)) => {
                    merge_sticker_pack(db, &storage_id, &sp)?;
                    debug!("merged sticker_pack record from storage");
                }
                Some(signal_rs_protos::storage_record::Record::CallLink(cl)) => {
                    merge_call_link(db, &storage_id, &cl)?;
                    debug!("merged call_link record from storage");
                }
                _ => {
                    debug!("skipping unknown storage record type");
                    skipped += 1;
                }
            }
        }

        // Persist the raw manifest data and update the version
        db.set_kv_blob("storage_manifest_data", &manifest_data)?;
        set_manifest_version(db, server_version)?;

        info!(
            old_version = local_version,
            new_version = server_version,
            contacts_merged,
            groups_merged,
            account_merged,
            skipped,
            "storage sync complete"
        );

        Ok(())
    }

    /// Write pending local changes to the storage service.
    ///
    /// Encrypts and uploads any locally modified records to the server.
    pub async fn push_changes(
        &self,
        db: &Database,
        storage_api: &StorageApi<'_>,
    ) -> Result<()> {
        debug!("pushing local changes to storage service");

        let local_version = get_manifest_version(db)?;

        // Derive storage key
        let master_key = get_effective_master_key(db)?;
        let storage_key = derive_storage_key(&master_key)?;

        // Collect all record identifiers from the local store
        let mut identifiers = Vec::new();
        let mut insert_items = Vec::new();

        // Collect contact records
        let recipients = db.list_all_recipients()?;
        for r in &recipients {
            if let Some(ref storage_id) = r.storage_id
                && let Some(ref storage_blob) = r.storage_record {
                    let item_key = derive_item_key(&storage_key, storage_id)?;
                    let encrypted = encrypt_aes256gcm(&item_key, storage_blob)?;
                    insert_items.push(StorageItem {
                        key: storage_id.clone(),
                        value: encrypted,
                    });
                    identifiers.push(manifest_record::Identifier {
                        raw: storage_id.clone(),
                        r#type: manifest_record::identifier::Type::Contact as i32,
                    });
                }
        }

        // Build a ManifestRecord
        let new_version = local_version + 1;
        let manifest_record = ManifestRecord {
            version: new_version,
            source_device: 0,
            identifiers,
            record_ikm: Vec::new(),
        };

        // Encode and encrypt the ManifestRecord with version-specific key
        let manifest_record_bytes = manifest_record.encode_to_vec();
        let manifest_key = derive_manifest_key(&storage_key, new_version)?;
        let encrypted_manifest = encrypt_aes256gcm(&manifest_key, &manifest_record_bytes)?;

        // Build the outer StorageManifest
        let storage_manifest = StorageManifest {
            version: new_version,
            value: encrypted_manifest,
        };

        // Build the WriteOperation
        let write_op = WriteOperation {
            manifest: Some(storage_manifest),
            insert_item: insert_items,
            delete_key: Vec::new(),
            clear_all: false,
        };

        let write_op_bytes = write_op.encode_to_vec();
        storage_api.write_manifest(&write_op_bytes).await?;

        set_manifest_version(db, new_version)?;

        info!(
            version = new_version,
            "storage changes pushed"
        );

        Ok(())
    }

    /// Read and decrypt the storage manifest.
    ///
    /// Downloads the manifest from the server, decrypts it using the
    /// storage key derived from the master key, and parses the contents.
    pub async fn read_manifest(
        &self,
        db: &Database,
        storage_api: &StorageApi<'_>,
    ) -> Result<()> {
        debug!("reading storage manifest");

        let manifest_data = storage_api.get_manifest().await?;

        // Derive storage key from master key (or AEP)
        let master_key = get_effective_master_key(db)?;
        let storage_key = derive_storage_key(&master_key)?;

        // Decode the outer StorageManifest
        let storage_manifest = StorageManifest::decode(manifest_data.as_slice())
            .map_err(|e| ManagerError::Other(format!("failed to decode StorageManifest: {e}")))?;

        let version = storage_manifest.version;

        // Decrypt the manifest value using version-specific key
        if !storage_manifest.value.is_empty() {
            let manifest_key = derive_manifest_key(&storage_key, version)?;
            let decrypted = decrypt_aes256gcm(&manifest_key, &storage_manifest.value)?;
            let manifest_record = ManifestRecord::decode(decrypted.as_slice())
                .map_err(|e| ManagerError::Other(format!("failed to decode ManifestRecord: {e}")))?;

            info!(
                version,
                record_count = manifest_record.identifiers.len(),
                "storage manifest read and decrypted"
            );
        } else {
            info!(version, "storage manifest has no encrypted data");
        }

        // Store the raw manifest data and update version
        db.set_kv_blob("storage_manifest_data", &manifest_data)?;
        set_manifest_version(db, version)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Record merging helpers
// ---------------------------------------------------------------------------

use signal_rs_protos::manifest_record;

/// Merge a contact record from the storage service into the local database.
fn merge_contact(
    db: &Database,
    storage_id: &[u8],
    contact: &signal_rs_protos::ContactRecord,
) -> Result<()> {
    if contact.aci.is_empty() {
        debug!("skipping contact record with no ACI");
        return Ok(());
    }

    let mut recipient = db.get_or_create_recipient(&contact.aci)?;

    // Update storage reference
    recipient.storage_id = Some(storage_id.to_vec());
    // Store the raw protobuf for future push operations
    recipient.storage_record = Some(contact.encode_to_vec());

    // Merge fields from the contact record
    if !contact.e164.is_empty() {
        recipient.number = Some(contact.e164.clone());
    }
    if !contact.pni.is_empty() {
        recipient.pni = Some(contact.pni.clone());
    }
    if !contact.username.is_empty() {
        recipient.username = Some(contact.username.clone());
    }
    if !contact.given_name.is_empty() {
        recipient.given_name = Some(contact.given_name.clone());
    }
    if !contact.family_name.is_empty() {
        recipient.family_name = Some(contact.family_name.clone());
    }
    if !contact.profile_key.is_empty() {
        recipient.profile_key = Some(contact.profile_key.clone());
    }
    recipient.blocked = contact.blocked;
    recipient.profile_sharing = contact.whitelisted;
    recipient.archived = contact.archived;
    recipient.hide_story = contact.hide_story;
    recipient.hidden = contact.hidden;
    recipient.mute_until = contact.mute_until_timestamp as i64;
    if contact.unregistered_at_timestamp > 0 {
        recipient.unregistered_timestamp = Some(contact.unregistered_at_timestamp as i64);
    }
    if !contact.system_given_name.is_empty() {
        recipient.nick_name_given_name = Some(contact.system_given_name.clone());
    }
    if !contact.system_family_name.is_empty() {
        recipient.nick_name_family_name = Some(contact.system_family_name.clone());
    }
    if !contact.note.is_empty() {
        recipient.note = Some(contact.note.clone());
    }

    db.update_recipient(&recipient)?;

    // Ensure a thread exists so the contact appears in the conversation list.
    let _ = db.get_or_create_thread_for_recipient(recipient.id);

    debug!(aci = %contact.aci, "merged contact record from storage");
    Ok(())
}

/// Merge a GroupV2 record from the storage service into the local database.
fn merge_group_v2(
    db: &Database,
    storage_id: &[u8],
    group: &signal_rs_protos::GroupV2Record,
) -> Result<()> {
    if group.master_key.is_empty() {
        debug!("skipping group_v2 record with no master key");
        return Ok(());
    }

    // Derive group_id from master key (SHA-256 of master_key)
    use sha2::Digest;
    let group_id = sha2::Sha256::digest(&group.master_key).to_vec();

    if let Some(mut existing) = db.get_group_by_group_id(&group_id)? {
        existing.storage_id = Some(storage_id.to_vec());
        existing.storage_record = Some(group.encode_to_vec());
        existing.master_key = group.master_key.clone();
        existing.blocked = group.blocked;
        existing.profile_sharing = group.whitelisted;
        db.save_group(&existing)?;
        // Ensure a thread exists so the group appears in the conversation list.
        let _ = db.get_or_create_thread_for_group(existing.id);
    } else {
        let new_group = signal_rs_store::models::group::GroupV2 {
            id: 0,
            group_id: group_id.clone(),
            master_key: group.master_key.clone(),
            group_data: None,
            distribution_id: uuid::Uuid::new_v4().as_bytes().to_vec(),
            blocked: group.blocked,
            permission_denied: false,
            storage_id: Some(storage_id.to_vec()),
            storage_record: Some(group.encode_to_vec()),
            profile_sharing: group.whitelisted,
            endorsement_expiration_time: 0,
        };
        db.save_group(&new_group)?;
        // Look up the newly-saved group to get its row ID, then create a thread.
        if let Some(saved) = db.get_group_by_group_id(&group_id)? {
            let _ = db.get_or_create_thread_for_group(saved.id);
        }
    }

    debug!("merged group_v2 record from storage");
    Ok(())
}

/// Merge an account record from the storage service into the local database.
fn merge_account(
    db: &Database,
    _storage_id: &[u8],
    account: &signal_rs_protos::AccountRecord,
) -> Result<()> {
    // Store individual account settings in the key-value store
    if !account.profile_key.is_empty() {
        db.set_kv_blob(account_keys::PROFILE_KEY, &account.profile_key)?;
    }
    if !account.given_name.is_empty() {
        db.set_kv_string("account_given_name", &account.given_name)?;
    }
    if !account.family_name.is_empty() {
        db.set_kv_string("account_family_name", &account.family_name)?;
    }
    if !account.avatar_url.is_empty() {
        db.set_kv_string("account_avatar_url", &account.avatar_url)?;
    }
    if !account.username.is_empty() {
        db.set_kv_string("account_username", &account.username)?;
    }
    db.set_kv_string("account_read_receipts", &account.read_receipts.to_string())?;
    db.set_kv_string("account_typing_indicators", &account.typing_indicators.to_string())?;
    db.set_kv_string("account_link_previews", &account.link_previews.to_string())?;
    db.set_kv_string("account_sealed_sender_indicators", &account.sealed_sender_indicators.to_string())?;
    if account.universal_expire_timer > 0 {
        db.set_kv_string("account_universal_expire_timer", &account.universal_expire_timer.to_string())?;
    }

    // Store the raw account record for future push
    let raw = account.encode_to_vec();
    db.set_kv_blob("storage_account_record", &raw)?;

    debug!("merged account record from storage");
    Ok(())
}

/// Merge a legacy GroupV1 record from the storage service into the local database.
///
/// GroupV1 is deprecated, so we store minimal info in the key-value store
/// keyed by the hex-encoded group ID for reference purposes.
fn merge_group_v1(
    db: &Database,
    _storage_id: &[u8],
    group: &signal_rs_protos::GroupV1Record,
) -> Result<()> {
    if group.id.is_empty() {
        debug!("skipping group_v1 record with no id");
        return Ok(());
    }

    let group_id_hex = hex::encode(&group.id);
    let key = format!("gv1:{group_id_hex}");

    // Store the raw protobuf so we can push it back later.
    db.set_kv_blob(&key, &group.encode_to_vec())?;

    // Persist boolean flags as a simple JSON-like string for easy reading.
    let blocked = group.blocked;
    let archived = group.archived;
    let meta = format!("blocked={blocked},archived={archived}");
    db.set_kv_string(&format!("gv1_meta:{group_id_hex}"), &meta)?;

    debug!(group_id = %group_id_hex, "merged group_v1 record from storage");
    Ok(())
}

/// Merge a StoryDistributionList record from the storage service into the
/// local database.
///
/// Stores the list identifier, name, and member service IDs in the key-value
/// store under the prefix `story_dist_list:`.
fn merge_story_distribution_list(
    db: &Database,
    _storage_id: &[u8],
    sdl: &signal_rs_protos::StoryDistributionListRecord,
) -> Result<()> {
    if sdl.identifier.is_empty() {
        debug!("skipping story_distribution_list record with no identifier");
        return Ok(());
    }

    let list_id_hex = hex::encode(&sdl.identifier);
    let key = format!("story_dist_list:{list_id_hex}");

    // Store the raw protobuf.
    db.set_kv_blob(&key, &sdl.encode_to_vec())?;

    // Store the name separately for easy display.
    if !sdl.name.is_empty() {
        db.set_kv_string(&format!("story_dist_list_name:{list_id_hex}"), &sdl.name)?;
    }

    debug!(list_id = %list_id_hex, "merged story_distribution_list record from storage");
    Ok(())
}

/// Merge a StickerPack record from the storage service into the local
/// database.
///
/// Stores pack_id and pack_key in the key-value store under the prefix
/// `sticker_pack:`.
fn merge_sticker_pack(
    db: &Database,
    _storage_id: &[u8],
    sp: &signal_rs_protos::StickerPackRecord,
) -> Result<()> {
    if sp.pack_id.is_empty() {
        debug!("skipping sticker_pack record with no pack_id");
        return Ok(());
    }

    let pack_id_hex = hex::encode(&sp.pack_id);
    let key = format!("sticker_pack:{pack_id_hex}");

    // Store the raw protobuf (contains pack_key, position, deleted_at).
    db.set_kv_blob(&key, &sp.encode_to_vec())?;

    // Store the pack_key separately for easy access.
    if !sp.pack_key.is_empty() {
        db.set_kv_blob(&format!("sticker_pack_key:{pack_id_hex}"), &sp.pack_key)?;
    }

    debug!(pack_id = %pack_id_hex, "merged sticker_pack record from storage");
    Ok(())
}

/// Merge a CallLink record from the storage service into the local database.
///
/// Stores root_key and admin_passkey in the key-value store under the prefix
/// `call_link:`.
fn merge_call_link(
    db: &Database,
    _storage_id: &[u8],
    cl: &signal_rs_protos::CallLinkRecord,
) -> Result<()> {
    if cl.root_key.is_empty() {
        debug!("skipping call_link record with no root_key");
        return Ok(());
    }

    let root_key_hex = hex::encode(&cl.root_key);
    let key = format!("call_link:{root_key_hex}");

    // Store the raw protobuf.
    db.set_kv_blob(&key, &cl.encode_to_vec())?;

    // Store admin passkey separately if present.
    if !cl.admin_passkey.is_empty() {
        db.set_kv_blob(&format!("call_link_admin:{root_key_hex}"), &cl.admin_passkey)?;
    }

    debug!(root_key = %root_key_hex, "merged call_link record from storage");
    Ok(())
}

/// Summary of records processed during a storage sync.
#[derive(Debug, Default)]
pub struct SyncSummary {
    /// Number of contact records merged.
    pub contacts: u32,
    /// Number of group V2 records merged.
    pub groups: u32,
    /// Whether an account record was merged.
    pub account: bool,
    /// Number of records that were skipped (unsupported type, decrypt failure, etc.).
    pub skipped: u32,
}

/// Process a batch of encrypted storage records.
///
/// Decrypts each record using the given storage key (and optional record_ikm),
/// parses the protobuf, and routes to the appropriate merge function based on
/// record type. Returns a summary of what was processed.
pub fn process_storage_records(
    db: &Database,
    storage_key: &[u8; 32],
    record_ikm: Option<&[u8]>,
    items: &[StorageItem],
) -> Result<SyncSummary> {
    let mut summary = SyncSummary::default();

    for item in items {
        let storage_id = item.key.clone();
        if item.value.is_empty() {
            summary.skipped += 1;
            continue;
        }
        let encrypted_value = &item.value;

        // Skip items too short for AES-256-GCM (nonce + tag minimum)
        if encrypted_value.len() < NONCE_SIZE + 16 {
            summary.skipped += 1;
            continue;
        }

        // Derive per-item key: record_ikm (HKDF) if available, else storage_key (HMAC)
        let item_key = match derive_effective_item_key(storage_key, record_ikm, &storage_id) {
            Ok(k) => k,
            Err(e) => {
                warn!("failed to derive item key: {e}");
                summary.skipped += 1;
                continue;
            }
        };

        let decrypted = match decrypt_aes256gcm(&item_key, encrypted_value) {
            Ok(d) => d,
            Err(e) => {
                warn!("failed to decrypt storage record: {e}");
                summary.skipped += 1;
                continue;
            }
        };

        let record = match StorageRecord::decode(decrypted.as_slice()) {
            Ok(r) => r,
            Err(e) => {
                warn!("failed to decode StorageRecord: {e}");
                summary.skipped += 1;
                continue;
            }
        };

        match record.record {
            Some(signal_rs_protos::storage_record::Record::Contact(contact)) => {
                merge_contact(db, &storage_id, &contact)?;
                summary.contacts += 1;
            }
            Some(signal_rs_protos::storage_record::Record::GroupV2(group)) => {
                merge_group_v2(db, &storage_id, &group)?;
                summary.groups += 1;
            }
            Some(signal_rs_protos::storage_record::Record::Account(account)) => {
                merge_account(db, &storage_id, &account)?;
                summary.account = true;
            }
            Some(signal_rs_protos::storage_record::Record::GroupV1(group_v1)) => {
                merge_group_v1(db, &storage_id, &group_v1)?;
            }
            Some(signal_rs_protos::storage_record::Record::StoryDistributionList(sdl)) => {
                merge_story_distribution_list(db, &storage_id, &sdl)?;
            }
            Some(signal_rs_protos::storage_record::Record::StickerPack(sp)) => {
                merge_sticker_pack(db, &storage_id, &sp)?;
            }
            Some(signal_rs_protos::storage_record::Record::CallLink(cl)) => {
                merge_call_link(db, &storage_id, &cl)?;
            }
            _ => {
                debug!("skipping unknown storage record type");
                summary.skipped += 1;
            }
        }
    }

    info!(
        contacts = summary.contacts,
        groups = summary.groups,
        account = summary.account,
        skipped = summary.skipped,
        "processed storage records"
    );

    Ok(summary)
}

/// Get the current manifest version from the local store.
fn get_manifest_version(db: &Database) -> Result<u64> {
    match db.get_kv_string(STORAGE_MANIFEST_VERSION_KEY)? {
        Some(s) => s.parse::<u64>().map_err(|e| {
            ManagerError::Other(format!("invalid manifest version: {e}"))
        }),
        None => Ok(0),
    }
}

/// Set the manifest version in the local store.
fn set_manifest_version(db: &Database, version: u64) -> Result<()> {
    db.set_kv_string(STORAGE_MANIFEST_VERSION_KEY, &version.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_rs_protos::{ContactRecord, GroupV2Record, AccountRecord, StorageItem};

    /// Helper: encrypt a protobuf record into a StorageItem using per-item key.
    fn make_encrypted_item(storage_key: &[u8; 32], storage_id: &[u8], record: &StorageRecord) -> StorageItem {
        let plaintext = record.encode_to_vec();
        let item_key = derive_item_key(storage_key, storage_id).unwrap();
        let encrypted = encrypt_aes256gcm(&item_key, &plaintext).unwrap();
        StorageItem {
            key: storage_id.to_vec(),
            value: encrypted,
        }
    }

    fn test_storage_key() -> [u8; 32] {
        // Derive a deterministic key from a fake master key.
        derive_storage_key(&[0x42u8; 32]).unwrap()
    }

    // ---- merge_contact tests ----

    #[test]
    fn merge_contact_creates_new_recipient() {
        let db = Database::open_in_memory().unwrap();
        let aci = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let storage_id = vec![0x01; 16];

        let contact = ContactRecord {
            aci: aci.to_string(),
            e164: "+15551234567".to_string(),
            pni: "11111111-2222-3333-4444-555555555555".to_string(),
            profile_key: vec![0xAB; 32],
            given_name: "Alice".to_string(),
            family_name: "Smith".to_string(),
            username: "alice.01".to_string(),
            blocked: false,
            whitelisted: true,
            archived: false,
            hide_story: false,
            hidden: false,
            mute_until_timestamp: 0,
            note: "A note".to_string(),
            ..Default::default()
        };

        merge_contact(&db, &storage_id, &contact).unwrap();

        let r = db.get_recipient_by_aci(aci).unwrap().expect("should exist");
        assert_eq!(r.number.as_deref(), Some("+15551234567"));
        assert_eq!(r.pni.as_deref(), Some("11111111-2222-3333-4444-555555555555"));
        assert_eq!(r.given_name.as_deref(), Some("Alice"));
        assert_eq!(r.family_name.as_deref(), Some("Smith"));
        assert_eq!(r.username.as_deref(), Some("alice.01"));
        assert_eq!(r.profile_key.as_deref(), Some(&[0xAB; 32][..]));
        assert!(!r.blocked);
        assert!(r.profile_sharing);
        assert!(!r.archived);
        assert!(!r.hidden);
        assert_eq!(r.note.as_deref(), Some("A note"));
        assert_eq!(r.storage_id.as_deref(), Some(storage_id.as_slice()));
    }

    #[test]
    fn merge_contact_updates_existing_recipient() {
        let db = Database::open_in_memory().unwrap();
        let aci = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

        // Create initial recipient.
        let mut initial = db.get_or_create_recipient(aci).unwrap();
        initial.given_name = Some("OldName".to_string());
        initial.blocked = false;
        db.update_recipient(&initial).unwrap();

        // Merge a contact record that updates the name and blocks.
        let contact = ContactRecord {
            aci: aci.to_string(),
            given_name: "NewName".to_string(),
            blocked: true,
            ..Default::default()
        };

        merge_contact(&db, &[0x02; 16], &contact).unwrap();

        let updated = db.get_recipient_by_aci(aci).unwrap().unwrap();
        assert_eq!(updated.given_name.as_deref(), Some("NewName"));
        assert!(updated.blocked);
        // ID should be the same (updated, not duplicated).
        assert_eq!(updated.id, initial.id);
    }

    #[test]
    fn merge_contact_skips_empty_aci() {
        let db = Database::open_in_memory().unwrap();
        let contact = ContactRecord {
            aci: "".to_string(),
            given_name: "Ghost".to_string(),
            ..Default::default()
        };

        merge_contact(&db, &[0x03; 16], &contact).unwrap();

        // No recipient should have been created.
        let all = db.list_all_recipients().unwrap();
        assert!(all.is_empty());
    }

    // ---- merge_group_v2 tests ----

    #[test]
    fn merge_group_v2_creates_new_group() {
        let db = Database::open_in_memory().unwrap();
        let master_key = vec![0xAA; 32];
        let storage_id = vec![0x05; 16];

        let group = GroupV2Record {
            master_key: master_key.clone(),
            blocked: false,
            whitelisted: true,
            ..Default::default()
        };

        merge_group_v2(&db, &storage_id, &group).unwrap();

        // Derive expected group_id (SHA-256 of master_key).
        use sha2::Digest;
        let expected_group_id = sha2::Sha256::digest(&master_key).to_vec();

        let g = db.get_group_by_group_id(&expected_group_id).unwrap().expect("group should exist");
        assert_eq!(g.master_key, master_key);
        assert!(!g.blocked);
        assert!(g.profile_sharing);
        assert_eq!(g.storage_id.as_deref(), Some(storage_id.as_slice()));
    }

    #[test]
    fn merge_group_v2_updates_existing_group() {
        let db = Database::open_in_memory().unwrap();
        let master_key = vec![0xBB; 32];

        use sha2::Digest;
        let group_id = sha2::Sha256::digest(&master_key).to_vec();

        // Insert a group first.
        db.insert_group(&group_id, &master_key, &[0x00; 16]).unwrap();

        let group = GroupV2Record {
            master_key: master_key.clone(),
            blocked: true,
            whitelisted: false,
            ..Default::default()
        };

        merge_group_v2(&db, &[0x06; 16], &group).unwrap();

        let g = db.get_group_by_group_id(&group_id).unwrap().unwrap();
        assert!(g.blocked);
        assert!(!g.profile_sharing);
    }

    #[test]
    fn merge_group_v2_skips_empty_master_key() {
        let db = Database::open_in_memory().unwrap();
        let group = GroupV2Record {
            master_key: Vec::new(),
            ..Default::default()
        };

        merge_group_v2(&db, &[0x07; 16], &group).unwrap();
        assert!(db.list_all_groups().unwrap().is_empty());
    }

    // ---- merge_account tests ----

    #[test]
    fn merge_account_stores_settings() {
        let db = Database::open_in_memory().unwrap();

        let account = AccountRecord {
            profile_key: vec![0xCC; 32],
            given_name: "Bob".to_string(),
            family_name: "Jones".to_string(),
            avatar_url: "https://example.com/avatar.jpg".to_string(),
            username: "bob.42".to_string(),
            read_receipts: true,
            typing_indicators: false,
            link_previews: true,
            sealed_sender_indicators: true,
            universal_expire_timer: 3600,
            ..Default::default()
        };

        merge_account(&db, &[0x08; 16], &account).unwrap();

        // Verify all settings were stored.
        assert_eq!(
            db.get_kv_blob(account_keys::PROFILE_KEY).unwrap().as_deref(),
            Some(&[0xCC; 32][..])
        );
        assert_eq!(
            db.get_kv_string("account_given_name").unwrap().as_deref(),
            Some("Bob")
        );
        assert_eq!(
            db.get_kv_string("account_family_name").unwrap().as_deref(),
            Some("Jones")
        );
        assert_eq!(
            db.get_kv_string("account_avatar_url").unwrap().as_deref(),
            Some("https://example.com/avatar.jpg")
        );
        assert_eq!(
            db.get_kv_string("account_username").unwrap().as_deref(),
            Some("bob.42")
        );
        assert_eq!(
            db.get_kv_string("account_read_receipts").unwrap().as_deref(),
            Some("true")
        );
        assert_eq!(
            db.get_kv_string("account_typing_indicators").unwrap().as_deref(),
            Some("false")
        );
        assert_eq!(
            db.get_kv_string("account_link_previews").unwrap().as_deref(),
            Some("true")
        );
        assert_eq!(
            db.get_kv_string("account_sealed_sender_indicators").unwrap().as_deref(),
            Some("true")
        );
        assert_eq!(
            db.get_kv_string("account_universal_expire_timer").unwrap().as_deref(),
            Some("3600")
        );

        // Raw account record should be stored.
        let raw = db.get_kv_blob("storage_account_record").unwrap();
        assert!(raw.is_some());
    }

    // ---- process_storage_records tests ----

    #[test]
    fn process_storage_records_mixed_types() {
        let db = Database::open_in_memory().unwrap();
        let storage_key = test_storage_key();

        // Build a contact record.
        let contact_record = StorageRecord {
            record: Some(signal_rs_protos::storage_record::Record::Contact(ContactRecord {
                aci: "11111111-1111-1111-1111-111111111111".to_string(),
                given_name: "Contact1".to_string(),
                ..Default::default()
            })),
        };

        // Build a group record.
        let group_record = StorageRecord {
            record: Some(signal_rs_protos::storage_record::Record::GroupV2(GroupV2Record {
                master_key: vec![0xDD; 32],
                blocked: false,
                ..Default::default()
            })),
        };

        // Build an account record.
        let account_record = StorageRecord {
            record: Some(signal_rs_protos::storage_record::Record::Account(AccountRecord {
                given_name: "Me".to_string(),
                ..Default::default()
            })),
        };

        let items = vec![
            make_encrypted_item(&storage_key, &[0x10; 16], &contact_record),
            make_encrypted_item(&storage_key, &[0x20; 16], &group_record),
            make_encrypted_item(&storage_key, &[0x30; 16], &account_record),
            // An item with empty value should be skipped.
            StorageItem { key: vec![0x40; 16], value: Vec::new() },
        ];

        let summary = process_storage_records(&db, &storage_key, None, &items).unwrap();

        assert_eq!(summary.contacts, 1);
        assert_eq!(summary.groups, 1);
        assert!(summary.account);
        assert_eq!(summary.skipped, 1);

        // Verify the contact was created.
        let r = db.get_recipient_by_aci("11111111-1111-1111-1111-111111111111").unwrap();
        assert!(r.is_some());
        assert_eq!(r.unwrap().given_name.as_deref(), Some("Contact1"));

        // Verify the group was created.
        use sha2::Digest;
        let expected_gid = sha2::Sha256::digest([0xDD; 32]).to_vec();
        let g = db.get_group_by_group_id(&expected_gid).unwrap();
        assert!(g.is_some());

        // Verify the account name was stored.
        assert_eq!(
            db.get_kv_string("account_given_name").unwrap().as_deref(),
            Some("Me")
        );
    }

    #[test]
    fn process_storage_records_decrypt_failure_skips() {
        let db = Database::open_in_memory().unwrap();
        let storage_key = test_storage_key();

        // Create an item with garbage encrypted data.
        let bad_item = StorageItem {
            key: vec![0x50; 16],
            value: vec![0xFF; 8], // Too short for valid AES-GCM
        };

        let summary = process_storage_records(&db, &storage_key, None, &[bad_item]).unwrap();
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.contacts, 0);
    }

    // ---- encryption round-trip tests ----

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello world";

        let encrypted = encrypt_aes256gcm(&key, plaintext).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext);

        let decrypted = decrypt_aes256gcm(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_too_short_fails() {
        let key = [0x42u8; 32];
        let result = decrypt_aes256gcm(&key, &[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let encrypted = encrypt_aes256gcm(&key1, b"secret").unwrap();
        let result = decrypt_aes256gcm(&key2, &encrypted);
        assert!(result.is_err());
    }

    // ---- manifest version tests ----

    #[test]
    fn manifest_version_get_set() {
        let db = Database::open_in_memory().unwrap();

        // Default should be 0.
        assert_eq!(get_manifest_version(&db).unwrap(), 0);

        set_manifest_version(&db, 42).unwrap();
        assert_eq!(get_manifest_version(&db).unwrap(), 42);

        set_manifest_version(&db, 100).unwrap();
        assert_eq!(get_manifest_version(&db).unwrap(), 100);
    }

    // ---- derive_storage_key test ----

    #[test]
    fn derive_storage_key_deterministic() {
        let master_key = [0xAB; 32];
        let k1 = derive_storage_key(&master_key).unwrap();
        let k2 = derive_storage_key(&master_key).unwrap();
        assert_eq!(k1, k2);

        // Different master key should produce different storage key.
        let k3 = derive_storage_key(&[0xCD; 32]).unwrap();
        assert_ne!(k1, k3);
    }
}
