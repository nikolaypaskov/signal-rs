//! Manager context — holds lazily-initialized dependencies.
//!
//! The `Context` struct is the central dependency container for the manager.
//! It provides access to the store, service connections, and helper objects,
//! creating them lazily on first use.

use std::sync::OnceLock;

use signal_rs_service::config::ServiceConfig;
use signal_rs_service::credentials::ServiceCredentials;
use signal_rs_service::net::connection::ConnectionManager;
use signal_rs_store::Database;

use crate::helpers::send::SendHelper;
use crate::helpers::receive::ReceiveHelper;
use crate::helpers::group::GroupHelper;
use crate::helpers::contact::ContactHelper;
use crate::helpers::profile::ProfileHelper;
use crate::helpers::pre_key::PreKeyHelper;
use crate::helpers::identity::IdentityHelper;
use crate::helpers::attachment::AttachmentHelper;
use crate::helpers::sticker::StickerHelper;
use crate::helpers::storage::StorageHelper;
use crate::helpers::sync::SyncHelper;
use crate::helpers::recipient::RecipientHelper;
use crate::helpers::pin::PinHelper;
use crate::helpers::unidentified_access::UnidentifiedAccessHelper;

/// The shared context for all manager operations.
///
/// Holds references to the core dependencies and provides lazy
/// initialization of helper objects.
pub struct Context {
    /// The service configuration (URLs, trust roots, etc.).
    pub config: ServiceConfig,

    /// The SQLite database for persistent storage.
    pub store: Database,

    /// The connection manager for HTTP and WebSocket connections.
    pub service: ConnectionManager,

    // -- Lazily-initialized helpers -----------------------------------------

    /// Send helper (message encryption and delivery).
    send_helper: OnceLock<SendHelper>,

    /// Receive helper (message decryption and processing).
    receive_helper: OnceLock<ReceiveHelper>,

    /// Group helper (Groups v2 operations).
    group_helper: OnceLock<GroupHelper>,

    /// Contact helper (contact management).
    contact_helper: OnceLock<ContactHelper>,

    /// Profile helper (profile encryption/decryption).
    profile_helper: OnceLock<ProfileHelper>,

    /// Pre-key helper (key generation and refresh).
    pre_key_helper: OnceLock<PreKeyHelper>,

    /// Identity helper (safety number verification).
    identity_helper: OnceLock<IdentityHelper>,

    /// Attachment helper (upload/download/encrypt).
    attachment_helper: OnceLock<AttachmentHelper>,

    /// Sticker helper (sticker pack management).
    sticker_helper: OnceLock<StickerHelper>,

    /// Storage helper (storage service sync).
    storage_helper: OnceLock<StorageHelper>,

    /// Sync helper (multi-device sync).
    sync_helper: OnceLock<SyncHelper>,

    /// Recipient helper (contact discovery and resolution).
    recipient_helper: OnceLock<RecipientHelper>,

    /// PIN helper (registration lock PIN management).
    pin_helper: OnceLock<PinHelper>,

    /// Unidentified access helper (sealed sender).
    unidentified_access_helper: OnceLock<UnidentifiedAccessHelper>,
}

impl Context {
    /// Create a new context with the given dependencies (authenticated).
    pub fn new(
        config: ServiceConfig,
        store: Database,
        service: ConnectionManager,
    ) -> Self {
        Self {
            config,
            store,
            service,
            send_helper: OnceLock::new(),
            receive_helper: OnceLock::new(),
            group_helper: OnceLock::new(),
            contact_helper: OnceLock::new(),
            profile_helper: OnceLock::new(),
            pre_key_helper: OnceLock::new(),
            identity_helper: OnceLock::new(),
            attachment_helper: OnceLock::new(),
            sticker_helper: OnceLock::new(),
            storage_helper: OnceLock::new(),
            sync_helper: OnceLock::new(),
            recipient_helper: OnceLock::new(),
            pin_helper: OnceLock::new(),
            unidentified_access_helper: OnceLock::new(),
        }
    }

    /// Create a new context without credentials (for pre-registration use).
    pub fn unauthenticated(config: ServiceConfig, store: Database) -> Self {
        let service = ConnectionManager::unauthenticated(config.clone());
        Self::new(config, store, service)
    }

    /// Update the connection manager's credentials after registration.
    pub fn set_credentials(&mut self, credentials: ServiceCredentials) {
        self.service.set_credentials(credentials);
    }

    /// Get the send helper, initializing it on first use.
    pub fn send(&self) -> &SendHelper {
        self.send_helper.get_or_init(SendHelper::new)
    }

    /// Get the receive helper, initializing it on first use.
    pub fn receive(&self) -> &ReceiveHelper {
        self.receive_helper.get_or_init(ReceiveHelper::new)
    }

    /// Get the group helper, initializing it on first use.
    pub fn group(&self) -> &GroupHelper {
        self.group_helper.get_or_init(GroupHelper::new)
    }

    /// Get the contact helper, initializing it on first use.
    pub fn contact(&self) -> &ContactHelper {
        self.contact_helper.get_or_init(ContactHelper::new)
    }

    /// Get the profile helper, initializing it on first use.
    pub fn profile(&self) -> &ProfileHelper {
        self.profile_helper.get_or_init(ProfileHelper::new)
    }

    /// Get the pre-key helper, initializing it on first use.
    pub fn pre_key(&self) -> &PreKeyHelper {
        self.pre_key_helper.get_or_init(PreKeyHelper::new)
    }

    /// Get the identity helper, initializing it on first use.
    pub fn identity(&self) -> &IdentityHelper {
        self.identity_helper.get_or_init(IdentityHelper::new)
    }

    /// Get the attachment helper, initializing it on first use.
    pub fn attachment(&self) -> &AttachmentHelper {
        self.attachment_helper.get_or_init(AttachmentHelper::new)
    }

    /// Get the sticker helper, initializing it on first use.
    pub fn sticker(&self) -> &StickerHelper {
        self.sticker_helper.get_or_init(StickerHelper::new)
    }

    /// Get the storage helper, initializing it on first use.
    pub fn storage(&self) -> &StorageHelper {
        self.storage_helper.get_or_init(StorageHelper::new)
    }

    /// Get the sync helper, initializing it on first use.
    pub fn sync(&self) -> &SyncHelper {
        self.sync_helper.get_or_init(SyncHelper::new)
    }

    /// Get the recipient helper, initializing it on first use.
    pub fn recipient(&self) -> &RecipientHelper {
        self.recipient_helper.get_or_init(RecipientHelper::new)
    }

    /// Get the PIN helper, initializing it on first use.
    pub fn pin(&self) -> &PinHelper {
        self.pin_helper.get_or_init(PinHelper::new)
    }

    /// Get the unidentified access helper, initializing it on first use.
    pub fn unidentified_access(&self) -> &UnidentifiedAccessHelper {
        self.unidentified_access_helper
            .get_or_init(UnidentifiedAccessHelper::new)
    }
}
