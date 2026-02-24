//! Group V2 data model.

use rusqlite::Row;
use serde::{Deserialize, Serialize};

/// A group V2 record from the `group_v2` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupV2 {
    /// Primary key.
    pub id: i64,
    /// The group identifier bytes.
    pub group_id: Vec<u8>,
    /// The group master key bytes.
    pub master_key: Vec<u8>,
    /// Serialized group data (protobuf).
    pub group_data: Option<Vec<u8>>,
    /// Distribution ID for sender key distribution.
    pub distribution_id: Vec<u8>,
    /// Whether the group is blocked.
    pub blocked: bool,
    /// Whether permission was denied for this group.
    pub permission_denied: bool,
    /// Storage service ID.
    pub storage_id: Option<Vec<u8>>,
    /// Storage service record blob.
    pub storage_record: Option<Vec<u8>>,
    /// Whether profile sharing is enabled for this group.
    pub profile_sharing: bool,
    /// Endorsement expiration timestamp.
    pub endorsement_expiration_time: i64,
}

impl GroupV2 {
    /// Construct a `GroupV2` from a `rusqlite::Row`.
    ///
    /// Expects all columns from `SELECT * FROM group_v2`.
    pub fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("_id")?,
            group_id: row.get("group_id")?,
            master_key: row.get("master_key")?,
            group_data: row.get("group_data")?,
            distribution_id: row.get("distribution_id")?,
            blocked: row.get::<_, i64>("blocked")? != 0,
            permission_denied: row.get::<_, i64>("permission_denied")? != 0,
            storage_id: row.get("storage_id")?,
            storage_record: row.get("storage_record")?,
            profile_sharing: row.get::<_, i64>("profile_sharing")? != 0,
            endorsement_expiration_time: row.get("endorsement_expiration_time")?,
        })
    }
}

/// A group V2 member record from the `group_v2_member` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupV2Member {
    /// Primary key.
    pub id: i64,
    /// Foreign key to `group_v2._id`.
    pub group_id: i64,
    /// Foreign key to `recipient._id`.
    pub recipient_id: i64,
    /// Endorsement bytes.
    pub endorsement: Vec<u8>,
}

impl GroupV2Member {
    /// Construct a `GroupV2Member` from a `rusqlite::Row`.
    pub fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("_id")?,
            group_id: row.get("group_id")?,
            recipient_id: row.get("recipient_id")?,
            endorsement: row.get("endorsement")?,
        })
    }
}
