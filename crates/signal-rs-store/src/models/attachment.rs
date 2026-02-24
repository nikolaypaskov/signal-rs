//! Attachment data model.

use serde::{Deserialize, Serialize};

/// An attachment associated with a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: Option<i64>,
    pub message_id: i64,
    pub content_type: String,
    pub file_name: Option<String>,
    pub size: Option<i64>,
    pub cdn_id: Option<String>,
    pub cdn_number: Option<u32>,
    pub key: Option<Vec<u8>>,
    pub digest: Option<Vec<u8>>,
    pub local_path: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub caption: Option<String>,
    pub upload_timestamp: Option<i64>,
}
