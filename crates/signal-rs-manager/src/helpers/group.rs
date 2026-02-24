//! Group helper -- Groups v2 operations.
//!
//! Responsible for:
//! - Creating groups (generating master key, deriving group ID via zkgroup, encrypting members)
//! - Updating group state (name, members, access control) via GroupChange.Actions protobuf
//! - Decrypting group state from the server
//! - Generating and distributing sender keys for group messaging
//! - Managing group invites and links

use prost::Message;
use tracing::{debug, info, warn};
use uuid::Uuid;

use signal_rs_protocol::stores::SenderKeyStore;
use signal_rs_protocol::{DeviceId, ProtocolAddress, SenderKeyRecord, ServiceId};
use signal_rs_service::api::groups_v2::GroupsV2Api;
use signal_rs_service::groups::GroupMasterKey;
use signal_rs_store::Database;

use crate::error::{ManagerError, Result};
use crate::types::{Group, GroupMember, GroupMemberRole, RecipientIdentifier};

/// Helper for group operations.
#[derive(Default)]
pub struct GroupHelper;

impl GroupHelper {
    /// Create a new group helper.
    pub fn new() -> Self {
        Self
    }

    /// Check whether the caller has permission to perform a group modification.
    ///
    /// Rules:
    /// - Admin-only operations: add/remove members, change group settings (title, avatar, access)
    /// - Any member: update own profile key, leave group
    ///
    /// The access control stored in the group protobuf determines who can edit
    /// attributes vs. who can add members. If the group has `Administrator`
    /// access control for members or attributes, only admins may perform those
    /// operations.
    pub fn check_permission(
        &self,
        db: &Database,
        group_id: &[u8],
        caller_uuid: &Uuid,
        is_member_change: bool,
        is_attribute_change: bool,
    ) -> Result<()> {
        // Look up stored group data for access control settings
        let stored_group = db
            .get_group_by_group_id(group_id)?
            .ok_or_else(|| {
                ManagerError::InvalidGroup("group not found in local store".to_string())
            })?;

        // Determine caller's role from the group protobuf data
        let caller_role = self.get_member_role_from_proto(
            db,
            &stored_group,
            caller_uuid,
        )?;

        // Decode access control from stored group data (if available)
        let (attr_access, member_access) = if let Some(ref data) = stored_group.group_data {
            if let Ok(group_proto) = signal_rs_protos::Group::decode(data.as_slice()) {
                let ac = group_proto.access_control.unwrap_or_default();
                (
                    ac.attributes.unwrap_or(0),
                    ac.members.unwrap_or(0),
                )
            } else {
                default_access_control()
            }
        } else {
            default_access_control()
        };

        let admin_level = signal_rs_protos::access_control::AccessRequired::Administrator as i32;

        // Check attribute modification permission
        if is_attribute_change && attr_access == admin_level
            && caller_role != GroupMemberRole::Administrator {
                return Err(ManagerError::PermissionDenied(
                    "only administrators can change group attributes".to_string(),
                ));
            }

        // Check member modification permission
        if is_member_change && member_access == admin_level
            && caller_role != GroupMemberRole::Administrator {
                return Err(ManagerError::PermissionDenied(
                    "only administrators can add or remove members".to_string(),
                ));
            }

        debug!(
            ?caller_role,
            is_member_change,
            is_attribute_change,
            "permission check passed"
        );
        Ok(())
    }

    /// Get the role of a member in a group by inspecting the cached group protobuf.
    ///
    /// Falls back to checking local membership (defaulting to Member role) if
    /// the group data is not available or the member is not found in the proto.
    fn get_member_role_from_proto(
        &self,
        db: &Database,
        stored_group: &signal_rs_store::models::group::GroupV2,
        member_uuid: &Uuid,
    ) -> Result<GroupMemberRole> {
        let master_key = GroupMasterKey::from_bytes(&stored_group.master_key)
            .map_err(|e| ManagerError::InvalidGroup(format!("bad master key: {e}")))?;
        let secret_params = master_key.derive_secret_params();

        // Try to determine role from cached group protobuf
        if let Some(ref data) = stored_group.group_data
            && let Ok(group_proto) = signal_rs_protos::Group::decode(data.as_slice()) {
                for member_proto in &group_proto.members {
                    if let Some(ref encrypted_user_id) = member_proto.user_id
                        && let Ok(decrypted_uuid) =
                            decrypt_uuid_with_params(&secret_params, encrypted_user_id)
                            && &decrypted_uuid == member_uuid {
                                let role = member_proto.role.unwrap_or(0);
                                let admin_role =
                                    signal_rs_protos::member::Role::Administrator as i32;
                                return Ok(if role == admin_role {
                                    GroupMemberRole::Administrator
                                } else {
                                    GroupMemberRole::Member
                                });
                            }
                }
            }

        // Fall back to local membership list
        let store_members = db.list_group_members(&stored_group.group_id)?;
        for store_member in store_members {
            if let Ok(Some(r)) = db.get_recipient_by_id(store_member.recipient_id) {
                let uuid = r.aci.as_ref().and_then(|s| Uuid::parse_str(s).ok());
                if uuid.as_ref() == Some(member_uuid) {
                    // Without protobuf data, default to Member role
                    return Ok(GroupMemberRole::Member);
                }
            }
        }

        Err(ManagerError::PermissionDenied(
            "you are not a member of this group".to_string(),
        ))
    }

    /// Create a new group with the given name and members.
    ///
    /// Generates a new master key, derives the group ID using zkgroup
    /// `GroupSecretParams`, builds a `Group` protobuf with encrypted fields,
    /// creates the group on the server, and stores it locally.
    pub async fn create(
        &self,
        db: &Database,
        groups_api: &GroupsV2Api<'_>,
        self_uuid: &Uuid,
        name: &str,
        members: &[RecipientIdentifier],
    ) -> Result<Group> {
        debug!(%name, member_count = members.len(), "creating group");

        // Generate master key and derive group ID via zkgroup
        let master_key = GroupMasterKey::generate();
        let group_id = master_key.derive_group_id();
        let distribution_id = Uuid::new_v4();
        let secret_params = master_key.derive_secret_params();

        // Insert the group into the local store
        db.insert_group(&group_id, &master_key.bytes, distribution_id.as_bytes())?;

        // Add self as administrator
        let self_recipient = db.get_or_create_recipient(&self_uuid.to_string())?;
        db.add_group_member(&group_id, self_recipient.id)?;

        let mut group_members = vec![GroupMember {
            uuid: *self_uuid,
            role: GroupMemberRole::Administrator,
            joined_at_revision: 0,
        }];

        // Build encrypted Member protobufs for the Group protobuf
        let mut proto_members = Vec::new();

        // Self as admin
        {
            let encrypted_user_id = encrypt_uuid_with_params(&secret_params, self_uuid);
            proto_members.push(signal_rs_protos::Member {
                user_id: Some(encrypted_user_id),
                role: Some(signal_rs_protos::member::Role::Administrator as i32),
                profile_key: None,
                presentation: None,
                joined_at_version: Some(0),
            });
        }

        // Add other members
        for member in members {
            match resolve_member(db, member) {
                Ok((recipient_id, uuid)) => {
                    db.add_group_member(&group_id, recipient_id)?;
                    group_members.push(GroupMember {
                        uuid,
                        role: GroupMemberRole::Member,
                        joined_at_revision: 0,
                    });

                    let encrypted_user_id = encrypt_uuid_with_params(&secret_params, &uuid);
                    proto_members.push(signal_rs_protos::Member {
                        user_id: Some(encrypted_user_id),
                        role: Some(signal_rs_protos::member::Role::Default as i32),
                        profile_key: None,
                        presentation: None,
                        joined_at_version: Some(0),
                    });
                }
                Err(e) => {
                    warn!(%member, error = %e, "failed to add member to group");
                }
            }
        }

        // Build the Group protobuf with encrypted fields
        let encrypted_title = master_key
            .encrypt_title(name)
            .unwrap_or_else(|_| name.as_bytes().to_vec());

        let public_key = zkgroup::serialize(&secret_params.get_public_params());

        let group_proto = signal_rs_protos::Group {
            public_key: Some(public_key),
            title: Some(encrypted_title),
            avatar: None,
            disappearing_messages_timer: None,
            access_control: Some(signal_rs_protos::AccessControl {
                attributes: Some(
                    signal_rs_protos::access_control::AccessRequired::Member as i32,
                ),
                members: Some(
                    signal_rs_protos::access_control::AccessRequired::Member as i32,
                ),
                add_from_invite_link: Some(
                    signal_rs_protos::access_control::AccessRequired::Unsatisfiable as i32,
                ),
            }),
            version: Some(0),
            members: proto_members,
            pending_members: Vec::new(),
            requesting_members: Vec::new(),
            invite_link_password: None,
            description_bytes: None,
            announcements_only: None,
            banned_members: Vec::new(),
        };

        // Serialize and upload the group to the server
        let group_bytes = group_proto.encode_to_vec();
        if let Err(e) = groups_api.create_group(&group_bytes).await {
            debug!(error = %e, "group creation API call failed (local group created)");
        }

        let group_id_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            group_id,
        );

        let group = Group {
            id: group_id_b64,
            name: name.to_string(),
            description: None,
            members: group_members,
            revision: 0,
            invite_link_enabled: false,
            disappearing_messages_timer: 0,
        };

        info!("group created successfully");
        Ok(group)
    }

    /// Fetch and decrypt the latest group state from the server.
    pub async fn fetch_group(
        &self,
        db: &Database,
        groups_api: &GroupsV2Api<'_>,
        group_id: &str,
    ) -> Result<Group> {
        debug!(%group_id, "fetching group state");

        let group_id_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            group_id,
        )
        .map_err(|e| ManagerError::InvalidGroup(format!("invalid base64: {e}")))?;

        let stored_group = db
            .get_group_by_group_id(&group_id_bytes)?
            .ok_or_else(|| ManagerError::InvalidGroup(group_id.to_string()))?;

        let master_key = GroupMasterKey::from_bytes(&stored_group.master_key)
            .map_err(|e| ManagerError::InvalidGroup(format!("bad master key: {e}")))?;

        // Fetch from server using serialized secret params
        let secret_params = master_key.derive_secret_params();
        let secret_params_bytes = zkgroup::serialize(&secret_params);
        let mut fetched_name = None;
        match groups_api.get_group(&secret_params_bytes).await {
            Ok(group_data) => {
                debug!(data_len = group_data.len(), "fetched group data from server");
                // Attempt to decode and decrypt the group state protobuf
                if let Ok(group_proto) =
                    signal_rs_protos::Group::decode(group_data.as_slice())
                {
                    if let Some(title_bytes) = &group_proto.title
                        && let Ok(title) = master_key.decrypt_title(title_bytes) {
                            fetched_name = Some(title);
                        }
                    // Store the raw group data for future reference
                    if let Err(e) = db.update_group_data(&group_id_bytes, &group_data) {
                        debug!(error = %e, "failed to cache group data");
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to fetch group from server, using local data");
            }
        }

        // Build from local store
        let store_members = db.list_group_members(&group_id_bytes)?;
        let mut members = Vec::new();
        for store_member in store_members {
            if let Ok(Some(r)) = db.get_recipient_by_id(store_member.recipient_id) {
                let uuid = r
                    .aci
                    .as_ref()
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .unwrap_or(Uuid::nil());
                members.push(GroupMember {
                    uuid,
                    role: GroupMemberRole::Member,
                    joined_at_revision: 0,
                });
            }
        }

        Ok(Group {
            id: group_id.to_string(),
            name: fetched_name.unwrap_or_default(),
            description: None,
            members,
            revision: 0,
            invite_link_enabled: false,
            disappearing_messages_timer: 0,
        })
    }

    /// Apply a group change (add/remove members, change name, etc.).
    ///
    /// Builds a proper `GroupChange.Actions` protobuf, encrypts member UUIDs
    /// and title using zkgroup, applies changes locally, and sends the
    /// serialized actions to the server.
    pub async fn apply_change(
        &self,
        db: &Database,
        groups_api: &GroupsV2Api<'_>,
        group_id: &str,
        name: Option<&str>,
        add_members: &[RecipientIdentifier],
        remove_members: &[RecipientIdentifier],
    ) -> Result<Group> {
        debug!(%group_id, ?name, "applying group change");

        let group_id_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            group_id,
        )
        .map_err(|e| ManagerError::InvalidGroup(format!("invalid base64: {e}")))?;

        let stored_group = db
            .get_group_by_group_id(&group_id_bytes)?
            .ok_or_else(|| ManagerError::InvalidGroup(group_id.to_string()))?;

        let master_key = GroupMasterKey::from_bytes(&stored_group.master_key)
            .map_err(|e| ManagerError::InvalidGroup(format!("bad master key: {e}")))?;
        let secret_params = master_key.derive_secret_params();

        // Build GroupChange.Actions protobuf
        let mut actions = signal_rs_protos::group_change::Actions {
            source_service_id: None,
            revision: None,
            add_members: Vec::new(),
            delete_members: Vec::new(),
            modify_member_roles: Vec::new(),
            modify_member_profile_keys: Vec::new(),
            add_pending_members: Vec::new(),
            delete_pending_members: Vec::new(),
            promote_pending_members: Vec::new(),
            modify_title: None,
            modify_avatar: None,
            modify_disappearing_messages_timer: None,
            modify_attributes_access: None,
            modify_member_access: None,
            modify_add_from_invite_link_access: None,
            add_requesting_members: Vec::new(),
            delete_requesting_members: Vec::new(),
            promote_requesting_members: Vec::new(),
            modify_invite_link_password: None,
            modify_description: None,
            modify_announcements_only: None,
            add_banned_members: Vec::new(),
            delete_banned_members: Vec::new(),
            promote_pending_pni_aci_members: Vec::new(),
        };

        // Add members (encrypt UUID with group secret params)
        for member in add_members {
            match resolve_member(db, member) {
                Ok((recipient_id, uuid)) => {
                    db.add_group_member(&group_id_bytes, recipient_id)?;

                    let encrypted_user_id = encrypt_uuid_with_params(&secret_params, &uuid);
                    let member_proto = signal_rs_protos::Member {
                        user_id: Some(encrypted_user_id),
                        role: Some(signal_rs_protos::member::Role::Default as i32),
                        profile_key: None,
                        presentation: None,
                        joined_at_version: None,
                    };
                    actions.add_members.push(
                        signal_rs_protos::group_change::actions::AddMemberAction {
                            added: Some(member_proto),
                            join_from_invite_link: Some(false),
                        },
                    );
                }
                Err(e) => {
                    warn!(%member, error = %e, "failed to add member");
                }
            }
        }

        // Remove members (encrypt UUID with group secret params)
        for member in remove_members {
            match resolve_member(db, member) {
                Ok((recipient_id, uuid)) => {
                    db.remove_group_member(&group_id_bytes, recipient_id)?;

                    let encrypted_user_id = encrypt_uuid_with_params(&secret_params, &uuid);
                    actions.delete_members.push(
                        signal_rs_protos::group_change::actions::DeleteMemberAction {
                            deleted_user_id: Some(encrypted_user_id),
                        },
                    );
                }
                Err(e) => {
                    warn!(%member, error = %e, "failed to remove member");
                }
            }
        }

        // Modify title (encrypt with zkgroup blob encryption)
        if let Some(new_name) = name {
            let encrypted_title = master_key
                .encrypt_title(new_name)
                .unwrap_or_else(|_| new_name.as_bytes().to_vec());
            actions.modify_title = Some(
                signal_rs_protos::group_change::actions::ModifyTitleAction {
                    title: Some(encrypted_title),
                },
            );
        }

        // Serialize and push changes to server
        let actions_bytes = actions.encode_to_vec();
        if let Err(e) = groups_api.modify_group(&actions_bytes).await {
            debug!(error = %e, "group modification API call failed (non-fatal)");
        }

        // Rebuild member list from local store
        let store_members = db.list_group_members(&group_id_bytes)?;
        let mut members = Vec::new();
        for store_member in store_members {
            if let Ok(Some(r)) = db.get_recipient_by_id(store_member.recipient_id) {
                let uuid = r
                    .aci
                    .as_ref()
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .unwrap_or(Uuid::nil());
                members.push(GroupMember {
                    uuid,
                    role: GroupMemberRole::Member,
                    joined_at_revision: 0,
                });
            }
        }

        let group = Group {
            id: group_id.to_string(),
            name: name.unwrap_or_default().to_string(),
            description: None,
            members,
            revision: 0,
            invite_link_enabled: false,
            disappearing_messages_timer: 0,
        };

        info!(%group_id, "group change applied");
        Ok(group)
    }

    /// Leave a group.
    ///
    /// Builds a `GroupChange.Actions` with a `DeleteMemberAction` for ourselves,
    /// removes us locally, and sends the change to the server.
    pub async fn leave(
        &self,
        db: &Database,
        groups_api: &GroupsV2Api<'_>,
        self_uuid: &Uuid,
        group_id: &str,
    ) -> Result<()> {
        debug!(%group_id, "leaving group");

        let group_id_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            group_id,
        )
        .map_err(|e| ManagerError::InvalidGroup(format!("invalid base64: {e}")))?;

        let stored_group = db
            .get_group_by_group_id(&group_id_bytes)?
            .ok_or_else(|| ManagerError::InvalidGroup(group_id.to_string()))?;

        let master_key = GroupMasterKey::from_bytes(&stored_group.master_key)
            .map_err(|e| ManagerError::InvalidGroup(format!("bad master key: {e}")))?;
        let secret_params = master_key.derive_secret_params();

        // Remove ourselves from the group locally
        let self_recipient = db.get_or_create_recipient(&self_uuid.to_string())?;
        db.remove_group_member(&group_id_bytes, self_recipient.id)?;

        // Build GroupChange.Actions with DeleteMember for self
        let encrypted_self_id = encrypt_uuid_with_params(&secret_params, self_uuid);
        let actions = signal_rs_protos::group_change::Actions {
            source_service_id: Some(encrypted_self_id.clone()),
            revision: None,
            add_members: Vec::new(),
            delete_members: vec![
                signal_rs_protos::group_change::actions::DeleteMemberAction {
                    deleted_user_id: Some(encrypted_self_id),
                },
            ],
            modify_member_roles: Vec::new(),
            modify_member_profile_keys: Vec::new(),
            add_pending_members: Vec::new(),
            delete_pending_members: Vec::new(),
            promote_pending_members: Vec::new(),
            modify_title: None,
            modify_avatar: None,
            modify_disappearing_messages_timer: None,
            modify_attributes_access: None,
            modify_member_access: None,
            modify_add_from_invite_link_access: None,
            add_requesting_members: Vec::new(),
            delete_requesting_members: Vec::new(),
            promote_requesting_members: Vec::new(),
            modify_invite_link_password: None,
            modify_description: None,
            modify_announcements_only: None,
            add_banned_members: Vec::new(),
            delete_banned_members: Vec::new(),
            promote_pending_pni_aci_members: Vec::new(),
        };

        let actions_bytes = actions.encode_to_vec();
        if let Err(e) = groups_api.modify_group(&actions_bytes).await {
            debug!(error = %e, "group leave API call failed (non-fatal)");
        }

        // Clear sender key shared state so new keys are distributed on rejoin
        if let Ok(dist_id) = parse_distribution_id(&stored_group.distribution_id)
            && let Err(e) = db.clear_sender_key_shared(&dist_id) {
                debug!(error = %e, "failed to clear sender key shared state");
            }

        info!(%group_id, "left group");
        Ok(())
    }

    /// Distribute our sender key to all group members who haven't received it yet.
    ///
    /// For each member who hasn't been sent our sender key distribution message,
    /// this creates a `SenderKeyDistributionMessage` and sends it as a 1:1
    /// message to that member. The distribution message is embedded in the
    /// Content protobuf's `sender_key_distribution_message` field.
    ///
    /// Returns the list of member UUIDs that need to receive the group message.
    pub fn get_members_needing_sender_key(
        &self,
        db: &Database,
        group_id: &[u8],
        distribution_id: &Uuid,
        self_uuid: &Uuid,
    ) -> Result<Vec<(Uuid, bool)>> {
        let store_members = db.list_group_members(group_id)?;
        let mut result = Vec::new();

        for store_member in store_members {
            let recipient = match db.get_recipient_by_id(store_member.recipient_id) {
                Ok(Some(r)) => r,
                _ => continue,
            };
            let uuid = match recipient.aci.as_ref().and_then(|s| Uuid::parse_str(s).ok()) {
                Some(u) => u,
                None => continue,
            };

            // Skip self
            if uuid == *self_uuid {
                continue;
            }

            let address_str = ServiceId::aci(uuid).to_string();
            let needs_key = !db
                .is_sender_key_shared(&address_str, DeviceId::PRIMARY.value(), distribution_id)
                .unwrap_or(false);

            result.push((uuid, needs_key));
        }

        Ok(result)
    }

    /// Create or retrieve our sender key for a group's distribution ID.
    ///
    /// If a sender key already exists in the store, returns it. Otherwise,
    /// generates a new 32-byte sender key, stores it, and returns it.
    pub fn ensure_sender_key(
        &self,
        db: &Database,
        self_uuid: &Uuid,
        distribution_id: &Uuid,
    ) -> Result<SenderKeyRecord> {
        let self_address = ProtocolAddress::new(
            ServiceId::aci(*self_uuid),
            DeviceId::PRIMARY,
        );

        // Check if we already have a sender key
        if let Ok(Some(existing)) = db.load_sender_key(&self_address, *distribution_id) {
            return Ok(existing);
        }

        // Generate a new 32-byte sender key
        let key_data: [u8; 32] = rand::random();
        let record = SenderKeyRecord::from_bytes(key_data.to_vec());

        db.store_sender_key(&self_address, *distribution_id, &record)
            .map_err(|e| ManagerError::Other(format!("failed to store sender key: {e}")))?;

        debug!(%distribution_id, "generated new sender key for group");
        Ok(record)
    }

    /// Build a sender key distribution message for the given distribution ID.
    ///
    /// The distribution message contains the distribution ID and the sender key
    /// material, allowing the recipient to decrypt future group messages.
    pub fn build_sender_key_distribution_message(
        &self,
        db: &Database,
        self_uuid: &Uuid,
        distribution_id: &Uuid,
    ) -> Result<Vec<u8>> {
        let sender_key = self.ensure_sender_key(db, self_uuid, distribution_id)?;

        // Build the distribution message:
        // [16 bytes: distribution ID (UUID)]
        // [remaining: sender key data]
        let mut message = Vec::with_capacity(16 + sender_key.serialize().len());
        message.extend_from_slice(distribution_id.as_bytes());
        message.extend_from_slice(sender_key.serialize());

        Ok(message)
    }

    /// Mark that a sender key has been shared with a recipient.
    pub fn mark_sender_key_shared(
        &self,
        db: &Database,
        member_uuid: &Uuid,
        distribution_id: &Uuid,
    ) -> Result<()> {
        let address_str = ServiceId::aci(*member_uuid).to_string();
        db.mark_sender_key_shared(
            &address_str,
            DeviceId::PRIMARY.value(),
            distribution_id,
        )?;
        Ok(())
    }

    /// Reset sender key shared state for a group.
    ///
    /// Call this when the group membership changes (member added or removed)
    /// so that sender keys are redistributed to all members.
    pub fn reset_sender_key_shared(
        &self,
        db: &Database,
        distribution_id: &Uuid,
    ) -> Result<()> {
        db.clear_sender_key_shared(distribution_id)?;
        debug!(%distribution_id, "reset sender key shared state for group");
        Ok(())
    }

    /// Encrypt a plaintext message using the group's sender key.
    ///
    /// Returns a sender key ciphertext in the format:
    /// - [16 bytes: distribution ID (UUID)]
    /// - [12 bytes: AES-GCM nonce]
    /// - [remaining: AES-256-GCM ciphertext + 16-byte auth tag]
    pub fn encrypt_for_group(
        &self,
        db: &Database,
        self_uuid: &Uuid,
        distribution_id: &Uuid,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let sender_key = self.ensure_sender_key(db, self_uuid, distribution_id)?;
        let key_data = sender_key.serialize();
        if key_data.len() < 32 {
            return Err(ManagerError::CryptoError(
                "sender key too short for AES-256".into(),
            ));
        }

        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use rand::RngCore;

        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_data[..32]);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
            ManagerError::CryptoError(format!("sender key AES-GCM encrypt failed: {e}"))
        })?;

        // Build the sender key message
        let mut message = Vec::with_capacity(16 + 12 + ciphertext.len());
        message.extend_from_slice(distribution_id.as_bytes());
        message.extend_from_slice(&nonce_bytes);
        message.extend_from_slice(&ciphertext);

        debug!(
            plaintext_len = plaintext.len(),
            ciphertext_len = message.len(),
            "encrypted message with sender key"
        );

        Ok(message)
    }
}

/// Encrypt a UUID using zkgroup `GroupSecretParams::encrypt_service_id`.
///
/// This produces the encrypted `user_id` field used in Member protobufs
/// for the group server. The result is the zkgroup-serialized `UuidCiphertext`.
pub(crate) fn encrypt_uuid_with_params(
    params: &zkgroup::groups::GroupSecretParams,
    uuid: &Uuid,
) -> Vec<u8> {
    let service_id = libsignal_core::Aci::from(*uuid);
    let ciphertext = params.encrypt_service_id(service_id.into());
    zkgroup::serialize(&ciphertext)
}

/// Decrypt a UUID from zkgroup-encrypted bytes using `GroupSecretParams`.
///
/// The encrypted bytes are a zkgroup-serialized `UuidCiphertext`.
/// Returns the decrypted UUID on success.
fn decrypt_uuid_with_params(
    params: &zkgroup::groups::GroupSecretParams,
    encrypted: &[u8],
) -> std::result::Result<Uuid, String> {
    let ciphertext: zkgroup::groups::UuidCiphertext =
        zkgroup::deserialize(encrypted).map_err(|e| format!("bad ciphertext: {e}"))?;
    let service_id = params
        .decrypt_service_id(ciphertext)
        .map_err(|e| format!("decrypt failed: {e}"))?;
    Ok(service_id.raw_uuid())
}

/// Default access control levels when no group data is available.
fn default_access_control() -> (i32, i32) {
    (
        signal_rs_protos::access_control::AccessRequired::Member as i32,
        signal_rs_protos::access_control::AccessRequired::Administrator as i32,
    )
}

/// Parse a distribution ID from stored bytes.
fn parse_distribution_id(bytes: &[u8]) -> std::result::Result<Uuid, &'static str> {
    if bytes.len() < 16 {
        return Err("distribution_id too short");
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    Ok(Uuid::from_bytes(buf))
}

/// Resolve a RecipientIdentifier to a (recipient_id, UUID) pair.
fn resolve_member(
    db: &Database,
    recipient: &RecipientIdentifier,
) -> Result<(i64, Uuid)> {
    match recipient {
        RecipientIdentifier::Uuid(uuid) => {
            let r = db.get_or_create_recipient(&uuid.to_string())?;
            Ok((r.id, *uuid))
        }
        RecipientIdentifier::PhoneNumber(number) => {
            let r = db
                .get_recipient_by_number(number)?
                .ok_or_else(|| ManagerError::Other(format!("recipient not found: {number}")))?;
            let uuid = r
                .aci
                .as_ref()
                .and_then(|s| Uuid::parse_str(s).ok())
                .unwrap_or(Uuid::nil());
            Ok((r.id, uuid))
        }
        RecipientIdentifier::Username(username) => {
            let r = db
                .get_recipient_by_username(username)?
                .ok_or_else(|| ManagerError::Other(format!("recipient not found: {username}")))?;
            let uuid = r
                .aci
                .as_ref()
                .and_then(|s| Uuid::parse_str(s).ok())
                .unwrap_or(Uuid::nil());
            Ok((r.id, uuid))
        }
    }
}
