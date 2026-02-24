//! Recipient data model.

use rusqlite::Row;
use serde::{Deserialize, Serialize};

/// A recipient record from the `recipient` table.
///
/// Represents a Signal contact with their profile data and conversation settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    /// Primary key.
    pub id: i64,
    /// Storage service ID (for sync).
    pub storage_id: Option<Vec<u8>>,
    /// Storage service record blob.
    pub storage_record: Option<Vec<u8>>,
    /// Phone number (E.164 format).
    pub number: Option<String>,
    /// Signal username.
    pub username: Option<String>,
    /// Account Identity (ACI) as a string UUID.
    pub aci: Option<String>,
    /// Phone Number Identity (PNI) as a string UUID.
    pub pni: Option<String>,
    /// Timestamp when the recipient was marked as unregistered, if applicable.
    pub unregistered_timestamp: Option<i64>,
    /// Profile key bytes.
    pub profile_key: Option<Vec<u8>>,
    /// Profile key credential bytes.
    pub profile_key_credential: Option<Vec<u8>>,

    /// Contact given name (local contact name, not profile name).
    pub given_name: Option<String>,
    /// Contact family name (local contact name).
    pub family_name: Option<String>,
    /// Nickname.
    pub nick_name: Option<String>,
    /// Conversation color.
    pub color: Option<String>,

    /// Disappearing message timer in seconds.
    pub expiration_time: i64,
    /// Mute until timestamp.
    pub mute_until: i64,
    /// Whether the recipient is blocked.
    pub blocked: bool,
    /// Whether the conversation is archived.
    pub archived: bool,
    /// Whether profile sharing is enabled.
    pub profile_sharing: bool,
    /// Whether stories from this recipient are hidden.
    pub hide_story: bool,
    /// Whether this contact is hidden.
    pub hidden: bool,
    /// Whether a PNI signature is needed.
    pub needs_pni_signature: bool,
    /// Whether this contact is discoverable.
    pub discoverable: Option<bool>,

    /// Nickname given name.
    pub nick_name_given_name: Option<String>,
    /// Nickname family name.
    pub nick_name_family_name: Option<String>,
    /// Contact note.
    pub note: Option<String>,
    /// Profile phone number sharing setting.
    pub profile_phone_number_sharing: Option<String>,
    /// Expiration time version.
    pub expiration_time_version: i64,

    /// Profile last update timestamp.
    pub profile_last_update_timestamp: i64,
    /// Profile given name (from Signal profile).
    pub profile_given_name: Option<String>,
    /// Profile family name (from Signal profile).
    pub profile_family_name: Option<String>,
    /// Profile about text.
    pub profile_about: Option<String>,
    /// Profile about emoji.
    pub profile_about_emoji: Option<String>,
    /// Profile avatar URL path.
    pub profile_avatar_url_path: Option<String>,
    /// Profile MobileCoin address.
    pub profile_mobile_coin_address: Option<Vec<u8>>,
    /// Profile unidentified access mode.
    pub profile_unidentified_access_mode: Option<String>,
    /// Profile capabilities (JSON string).
    pub profile_capabilities: Option<String>,
}

impl Recipient {
    /// Construct a `Recipient` from a `rusqlite::Row`.
    ///
    /// Expects all columns from `SELECT * FROM recipient`.
    pub fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("_id")?,
            storage_id: row.get("storage_id")?,
            storage_record: row.get("storage_record")?,
            number: row.get("number")?,
            username: row.get("username")?,
            aci: row.get("aci")?,
            pni: row.get("pni")?,
            unregistered_timestamp: row.get("unregistered_timestamp")?,
            profile_key: row.get("profile_key")?,
            profile_key_credential: row.get("profile_key_credential")?,
            given_name: row.get("given_name")?,
            family_name: row.get("family_name")?,
            nick_name: row.get("nick_name")?,
            color: row.get("color")?,
            expiration_time: row.get("expiration_time")?,
            mute_until: row.get("mute_until")?,
            blocked: row.get::<_, i64>("blocked")? != 0,
            archived: row.get::<_, i64>("archived")? != 0,
            profile_sharing: row.get::<_, i64>("profile_sharing")? != 0,
            hide_story: row.get::<_, i64>("hide_story")? != 0,
            hidden: row.get::<_, i64>("hidden")? != 0,
            needs_pni_signature: row.get::<_, i64>("needs_pni_signature")? != 0,
            discoverable: row.get::<_, Option<i64>>("discoverable")?.map(|v| v != 0),
            nick_name_given_name: row.get("nick_name_given_name")?,
            nick_name_family_name: row.get("nick_name_family_name")?,
            note: row.get("note")?,
            profile_phone_number_sharing: row.get("profile_phone_number_sharing")?,
            expiration_time_version: row.get("expiration_time_version")?,
            profile_last_update_timestamp: row.get("profile_last_update_timestamp")?,
            profile_given_name: row.get("profile_given_name")?,
            profile_family_name: row.get("profile_family_name")?,
            profile_about: row.get("profile_about")?,
            profile_about_emoji: row.get("profile_about_emoji")?,
            profile_avatar_url_path: row.get("profile_avatar_url_path")?,
            profile_mobile_coin_address: row.get("profile_mobile_coin_address")?,
            profile_unidentified_access_mode: row.get("profile_unidentified_access_mode")?,
            profile_capabilities: row.get("profile_capabilities")?,
        })
    }

    /// Return a display name for this recipient, preferring profile name,
    /// then contact name, then number, then ACI.
    pub fn display_name(&self) -> String {
        // Try profile name first.
        if let Some(ref given) = self.profile_given_name
            && !given.is_empty() {
                return match &self.profile_family_name {
                    Some(family) if !family.is_empty() => format!("{given} {family}"),
                    _ => given.clone(),
                };
            }
        // Try contact name.
        if let Some(ref given) = self.given_name
            && !given.is_empty() {
                return match &self.family_name {
                    Some(family) if !family.is_empty() => format!("{given} {family}"),
                    _ => given.clone(),
                };
            }
        // Try number.
        if let Some(ref number) = self.number {
            return number.clone();
        }
        // Fall back to ACI.
        if let Some(ref aci) = self.aci {
            return aci.clone();
        }
        format!("Recipient #{}", self.id)
    }
}
