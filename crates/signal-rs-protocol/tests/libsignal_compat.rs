//! Cross-library compatibility tests: signal-rs <-> libsignal
//!
//! Verifies that messages encrypted by our Signal Protocol implementation
//! can be parsed and decrypted by the official libsignal library.
//!
//! This is the most effective way to find protocol incompatibilities:
//! encrypt with our code, decrypt with the reference implementation.

// Import libsignal types — use wildcard to get all traits in scope
// (GenericSignedPreKey, PreKeyStore, SignedPreKeyStore, etc.)
use libsignal_protocol::*;
use prost::Message;

/// Helper: set up a PQXDH session with Bob (libsignal) as recipient
/// and Alice (signal-rs) as sender. Returns everything needed for tests.
struct TestSession {
    bob_store: InMemSignalProtocolStore,
    alice_identity: signal_rs_protocol::IdentityKeyPair,
    prekey_msg_bytes: Vec<u8>,
    plaintext: Vec<u8>,
    #[allow(dead_code)]
    alice_reg_id: u32,
    alice_uuid: String,
    rng: rand_09::rngs::ThreadRng,
}

async fn setup_test_session() -> TestSession {
    let mut rng = rand_09::rng();
    let bob_reg_id = 42u32;
    let alice_reg_id = 123u32;
    let alice_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string();

    let bob_identity = IdentityKeyPair::generate(&mut rng);
    let bob_spk = KeyPair::generate(&mut rng);
    let bob_spk_id: SignedPreKeyId = 1u32.into();
    let bob_spk_pub_bytes = bob_spk.public_key.serialize();
    let bob_spk_sig = bob_identity
        .private_key()
        .calculate_signature(&bob_spk_pub_bytes, &mut rng)
        .expect("SPK signature");

    let bob_opk = KeyPair::generate(&mut rng);
    let bob_opk_id: PreKeyId = 100u32.into();

    let bob_kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let bob_kyber_id: KyberPreKeyId = 200u32.into();
    let bob_kyber_pub_bytes = bob_kyber.public_key.serialize();
    let bob_kyber_sig = bob_identity
        .private_key()
        .calculate_signature(&bob_kyber_pub_bytes, &mut rng)
        .expect("Kyber signature");

    let bob_ik_serialized = bob_identity.identity_key().serialize();
    let bob_opk_pub_serialized = bob_opk.public_key.serialize();

    let mut bob_store = InMemSignalProtocolStore::new(bob_identity, bob_reg_id)
        .expect("create bob store");

    {
        let record = SignedPreKeyRecord::new(
            bob_spk_id,
            Timestamp::from_epoch_millis(42),
            &bob_spk,
            &bob_spk_sig,
        );
        bob_store
            .signed_pre_key_store
            .save_signed_pre_key(bob_spk_id, &record)
            .await
            .expect("save SPK");
    }
    {
        let record = PreKeyRecord::new(bob_opk_id, &bob_opk);
        bob_store
            .pre_key_store
            .save_pre_key(bob_opk_id, &record)
            .await
            .expect("save OPK");
    }
    {
        let record = KyberPreKeyRecord::new(
            bob_kyber_id,
            Timestamp::from_epoch_millis(42),
            &bob_kyber,
            &bob_kyber_sig,
        );
        bob_store
            .kyber_pre_key_store
            .save_kyber_pre_key(bob_kyber_id, &record)
            .await
            .expect("save Kyber");
    }

    let alice_identity = signal_rs_protocol::IdentityKeyPair::generate();

    let (mut session, kyber_ct) = signal_rs_protocol::SessionRecord::new_from_pre_key(
        &alice_identity,
        &bob_ik_serialized[1..],
        &bob_spk_pub_bytes[1..],
        Some(&bob_opk_pub_serialized[1..]),
        Some(&bob_kyber_pub_bytes),
    )
    .expect("PQXDH session creation");

    let plaintext = b"Hello from signal-rs!";
    let (cbc_ciphertext, counter, keys) = session.encrypt(plaintext).expect("encrypt");

    let sender_ik = alice_identity.public_key().serialize();
    let receiver_ik = session.remote_identity_key();
    let ratchet_key = session.local_ephemeral_public();

    let signal_msg_bytes = signal_rs_protocol::WireSignalMessage::serialize(
        ratchet_key,
        counter,
        session.previous_counter(),
        &cbc_ciphertext,
        &keys.mac_key,
        sender_ik,
        receiver_ik,
    );

    let base_key = session.base_key().expect("base key");

    let prekey_msg_bytes = signal_rs_protocol::WirePreKeySignalMessage::serialize(
        Some(100),
        base_key,
        sender_ik,
        &signal_msg_bytes,
        alice_reg_id,
        1,
        Some(200),
        kyber_ct.as_deref(),
    );

    TestSession {
        bob_store,
        alice_identity,
        prekey_msg_bytes,
        plaintext: plaintext.to_vec(),
        alice_reg_id,
        alice_uuid,
        rng,
    }
}

/// Test that libsignal can parse and decrypt a PreKeySignalMessage
/// produced by our signal-rs protocol implementation.
#[tokio::test]
async fn signal_rs_encrypt_libsignal_decrypt() {
    let mut t = setup_test_session().await;

    let device_id = DeviceId::try_from(1u32).expect("valid device id");
    let alice_address = ProtocolAddress::new(t.alice_uuid.clone(), device_id);

    let parsed = PreKeySignalMessage::try_from(t.prekey_msg_bytes.as_slice())
        .expect("libsignal should parse our PreKeySignalMessage");

    eprintln!("[OK] libsignal parsed PreKeySignalMessage (version={}, reg_id={})",
        parsed.message_version(), parsed.registration_id());

    let decrypted = message_decrypt_prekey(
        &parsed,
        &alice_address,
        &mut t.bob_store.session_store,
        &mut t.bob_store.identity_store,
        &mut t.bob_store.pre_key_store,
        &t.bob_store.signed_pre_key_store,
        &mut t.bob_store.kyber_pre_key_store,
        &mut t.rng,
    )
    .await
    .expect("libsignal should decrypt our message");

    assert_eq!(decrypted.as_slice(), &t.plaintext);
    eprintln!("=== SUCCESS: signal-rs -> libsignal PreKeySignalMessage roundtrip works! ===");
}

/// Test that libsignal can unseal a sealed-sender (type 6) message
/// produced by our signal-rs sealed_sender::seal() implementation.
///
/// This tests the outer sealed-sender crypto layer independently:
/// double ECDH + AES-256-CTR + HMAC-SHA256 (truncated to 10 bytes).
#[tokio::test]
async fn signal_rs_seal_libsignal_unseal() {
    let mut t = setup_test_session().await;

    let alice_uuid = uuid::Uuid::parse_str(&t.alice_uuid).unwrap();
    let alice_identity_pub_33 = t.alice_identity.public_key().serialize();

    // Get Bob's identity public key (33 bytes) for seal()
    let bob_identity_pub_33 = t.bob_store.identity_store
        .get_identity_key_pair()
        .await
        .expect("bob identity")
        .identity_key()
        .serialize()
        .to_vec();

    // Build a SenderCertificate using libsignal's API (requires signer field).
    // For sealed_sender_decrypt_to_usmc, the certificate signature is NOT validated
    // against the trust root — so we just need structurally valid protos.
    let mut rng2 = rand_09::rng();
    let trust_root = KeyPair::generate(&mut rng2);
    let server_key = KeyPair::generate(&mut rng2);

    let server_cert = ServerCertificate::new(
        1,
        server_key.public_key,
        &trust_root.private_key,
        &mut rng2,
    ).expect("create server cert");

    // Create Alice's identity as a libsignal PublicKey for the SenderCertificate
    let alice_pub_key = PublicKey::try_from(alice_identity_pub_33).expect("valid alice pub key");
    let alice_device_id = DeviceId::try_from(1u32).expect("valid device id");

    let sender_cert = SenderCertificate::new(
        t.alice_uuid.clone(),
        None, // no e164
        alice_pub_key,
        alice_device_id,
        Timestamp::from_epoch_millis(u64::MAX - 1),
        server_cert,
        &server_key.private_key,
        &mut rng2,
    ).expect("create sender cert");

    let sender_cert_bytes = sender_cert.serialized().expect("serialize sender cert").to_vec();

    eprintln!("[OK] Built mock SenderCertificate ({} bytes)", sender_cert_bytes.len());

    // Seal with our implementation
    let sealed = signal_rs_protocol::seal_sealed_sender(
        &t.prekey_msg_bytes,    // inner PreKeySignalMessage
        3,                       // wire type 3 = PreKey
        &sender_cert_bytes,
        &t.alice_identity,
        &bob_identity_pub_33,
        1,                       // RESENDABLE
        None,                    // no group
    )
    .expect("seal should succeed");

    eprintln!("[OK] Sealed sender message: {} bytes, version=0x{:02x}", sealed.len(), sealed[0]);
    assert_eq!(sealed[0], 0x11, "version byte should be 0x11 (V1)");

    // Unseal with libsignal's sealed_sender_decrypt_to_usmc
    let usmc = sealed_sender_decrypt_to_usmc(
        &sealed,
        &t.bob_store.identity_store,
    )
    .await;

    match usmc {
        Ok(usmc) => {
            eprintln!("[OK] libsignal unsealed our sealed-sender message!");
            eprintln!("  msg_type: {:?}", usmc.msg_type());
            eprintln!("  content_hint: {:?}", usmc.content_hint());
            eprintln!("  sender UUID: {}", usmc.sender().unwrap().sender_uuid().unwrap());
            eprintln!("  sender device: {:?}", usmc.sender().unwrap().sender_device_id());

            // Verify sender info
            assert_eq!(
                usmc.sender().unwrap().sender_uuid().unwrap(),
                alice_uuid.to_string(),
            );

            // The inner content should be our PreKeySignalMessage bytes
            let inner_content = usmc.contents().unwrap();
            eprintln!("  inner content: {} bytes", inner_content.len());

            // Try to parse the inner content as a PreKeySignalMessage
            let inner_parsed = PreKeySignalMessage::try_from(inner_content)
                .expect("inner content should be a valid PreKeySignalMessage");
            eprintln!("[OK] Inner PreKeySignalMessage parsed (version={})", inner_parsed.message_version());

            // Now decrypt the inner message
            let device_id = DeviceId::try_from(1u32).expect("valid device id");
            let alice_address = ProtocolAddress::new(t.alice_uuid.clone(), device_id);

            let decrypted = message_decrypt_prekey(
                &inner_parsed,
                &alice_address,
                &mut t.bob_store.session_store,
                &mut t.bob_store.identity_store,
                &mut t.bob_store.pre_key_store,
                &t.bob_store.signed_pre_key_store,
                &mut t.bob_store.kyber_pre_key_store,
                &mut t.rng,
            )
            .await
            .expect("inner message decryption should succeed");

            assert_eq!(decrypted.as_slice(), &t.plaintext);
            eprintln!("=== SUCCESS: signal-rs seal -> libsignal unseal+decrypt works! ===");
        }
        Err(e) => {
            eprintln!("[FAIL] libsignal could not unseal our sealed-sender message");
            eprintln!("  error: {e}");
            eprintln!("  debug: {e:?}");
            panic!("sealed sender unseal failed: {e}");
        }
    }
}

/// Test the full real-world pipeline: Content proto → pad → encrypt → seal →
/// unseal → decrypt → unpad → parse Content proto.
///
/// This catches issues that the raw-bytes test might miss, such as:
/// - Content proto encoding problems
/// - Padding/unpadding corruption
/// - Large message handling
#[tokio::test]
async fn signal_rs_real_content_roundtrip() {
    let mut t = setup_test_session().await;

    let _alice_uuid = uuid::Uuid::parse_str(&t.alice_uuid).unwrap();
    let timestamp: u64 = 1700000000000; // a realistic timestamp

    // Build a real Content proto with DataMessage (body + timestamp + profile_key)
    let data_message = signal_rs_protos::DataMessage {
        body: Some("Hello from signal-rs sealed sender!".to_string()),
        timestamp: Some(timestamp),
        profile_key: Some(vec![0xAA; 32]), // 32-byte profile key
        is_view_once: Some(false),
        ..Default::default()
    };
    let content = signal_rs_protos::Content {
        data_message: Some(data_message),
        ..Default::default()
    };
    let raw_proto = content.encode_to_vec();
    eprintln!("[OK] Content proto: {} bytes", raw_proto.len());

    // Pad using Signal's exponential bucket scheme
    let padded = {
        let with_boundary = raw_proto.len() + 1;
        let padded_size = std::cmp::max(541, {
            let size_f = with_boundary as f64;
            (1.05_f64).powf((size_f.ln() / 1.05_f64.ln()).ceil()).floor() as usize
        });
        let mut buf = Vec::with_capacity(padded_size);
        buf.extend_from_slice(&raw_proto);
        buf.push(0x80);
        buf.resize(padded_size, 0x00);
        buf
    };
    eprintln!("[OK] Padded plaintext: {} bytes", padded.len());

    // Encrypt with our session (same as setup_test_session but with real content)
    let alice_identity = &t.alice_identity;

    // We need a fresh session since setup_test_session already encrypted one message.
    // Re-derive from the pre-key bundle stored in bob_store.
    let bob_identity_pub_33 = t.bob_store.identity_store
        .get_identity_key_pair()
        .await
        .expect("bob identity")
        .identity_key()
        .serialize()
        .to_vec();

    // Create a fresh session for this test
    let bob_spk_id: SignedPreKeyId = 1u32.into();
    let bob_spk_record = t.bob_store.signed_pre_key_store
        .get_signed_pre_key(bob_spk_id)
        .await
        .expect("get SPK record");
    let bob_spk_pub = bob_spk_record.public_key().expect("SPK public");

    // Get Bob's one-time pre-key
    let bob_opk_id: PreKeyId = 100u32.into();
    let bob_opk_record = t.bob_store.pre_key_store
        .get_pre_key(bob_opk_id)
        .await
        .expect("get OPK record");
    let bob_opk_pub = bob_opk_record.public_key().expect("OPK public");

    // Get Bob's Kyber pre-key
    let bob_kyber_id: KyberPreKeyId = 200u32.into();
    let bob_kyber_record = t.bob_store.kyber_pre_key_store
        .get_kyber_pre_key(bob_kyber_id)
        .await
        .expect("get Kyber record");
    let bob_kyber_pub = bob_kyber_record.public_key().expect("Kyber public");

    let (mut session, kyber_ct) = signal_rs_protocol::SessionRecord::new_from_pre_key(
        alice_identity,
        &bob_identity_pub_33[1..],      // strip 0x05 prefix
        &bob_spk_pub.serialize()[1..],   // strip 0x05 prefix
        Some(&bob_opk_pub.serialize()[1..]),
        Some(&bob_kyber_pub.serialize()),
    )
    .expect("PQXDH session for real content test");

    // Encrypt the padded Content proto
    let (cbc_ciphertext, counter, keys) = session.encrypt(&padded).expect("encrypt padded content");
    eprintln!("[OK] Encrypted: {} bytes, counter={}", cbc_ciphertext.len(), counter);

    let sender_ik = alice_identity.public_key().serialize();
    let receiver_ik = session.remote_identity_key();
    let ratchet_key = session.local_ephemeral_public();

    let signal_msg_bytes = signal_rs_protocol::WireSignalMessage::serialize(
        ratchet_key,
        counter,
        session.previous_counter(),
        &cbc_ciphertext,
        &keys.mac_key,
        sender_ik,
        receiver_ik,
    );

    let base_key = session.base_key().expect("base key");
    let our_reg_id = 123u32;

    let prekey_msg_bytes = signal_rs_protocol::WirePreKeySignalMessage::serialize(
        Some(100),
        base_key,
        sender_ik,
        &signal_msg_bytes,
        our_reg_id,
        1,
        Some(200),
        kyber_ct.as_deref(),
    );
    eprintln!("[OK] PreKeySignalMessage: {} bytes", prekey_msg_bytes.len());

    // Build sender certificate
    let mut rng2 = rand_09::rng();
    let trust_root = KeyPair::generate(&mut rng2);
    let server_key = KeyPair::generate(&mut rng2);
    let server_cert = ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng2)
        .expect("server cert");
    let alice_pub_key = PublicKey::try_from(alice_identity.public_key().serialize())
        .expect("alice pub key");
    let alice_device_id = DeviceId::try_from(1u32).expect("device id");
    let sender_cert = SenderCertificate::new(
        t.alice_uuid.clone(), None, alice_pub_key, alice_device_id,
        Timestamp::from_epoch_millis(u64::MAX - 1), server_cert, &server_key.private_key, &mut rng2,
    ).expect("sender cert");
    let sender_cert_bytes = sender_cert.serialized().expect("serialize cert").to_vec();

    // Seal with our sealed sender
    let sealed = signal_rs_protocol::seal_sealed_sender(
        &prekey_msg_bytes, 3, &sender_cert_bytes, alice_identity, &bob_identity_pub_33, 1, None,
    ).expect("seal");
    eprintln!("[OK] Sealed: {} bytes", sealed.len());

    // Unseal with libsignal
    let usmc = sealed_sender_decrypt_to_usmc(&sealed, &t.bob_store.identity_store)
        .await
        .expect("unseal");
    eprintln!("[OK] Unsealed: msg_type={:?}", usmc.msg_type());

    // Decrypt with libsignal
    let inner_content = usmc.contents().unwrap();
    let inner_parsed = PreKeySignalMessage::try_from(inner_content)
        .expect("parse inner PreKeySignalMessage");

    let device_id = DeviceId::try_from(1u32).expect("valid device id");
    let alice_address = ProtocolAddress::new(t.alice_uuid.clone(), device_id);

    let decrypted = message_decrypt_prekey(
        &inner_parsed,
        &alice_address,
        &mut t.bob_store.session_store,
        &mut t.bob_store.identity_store,
        &mut t.bob_store.pre_key_store,
        &t.bob_store.signed_pre_key_store,
        &mut t.bob_store.kyber_pre_key_store,
        &mut t.rng,
    )
    .await
    .expect("decrypt inner message");

    eprintln!("[OK] Decrypted: {} bytes", decrypted.len());

    // Strip padding (same as strip_content_padding)
    let unpadded = {
        let bytes = decrypted.as_slice();
        let mut end = bytes.len();
        for i in (0..bytes.len()).rev() {
            if bytes[i] == 0x80 {
                end = i;
                break;
            } else if bytes[i] != 0x00 {
                break;
            }
        }
        &bytes[..end]
    };
    eprintln!("[OK] Unpadded: {} bytes (original proto was {} bytes)", unpadded.len(), raw_proto.len());
    assert_eq!(unpadded.len(), raw_proto.len(), "unpadded size should match original proto");

    // Parse the Content proto
    let decoded_content = signal_rs_protos::Content::decode(unpadded)
        .expect("parse Content proto");
    let decoded_dm = decoded_content.data_message.expect("should have DataMessage");
    assert_eq!(decoded_dm.body.as_deref(), Some("Hello from signal-rs sealed sender!"));
    assert_eq!(decoded_dm.timestamp, Some(timestamp));
    assert_eq!(decoded_dm.profile_key.as_deref(), Some(&[0xAA; 32][..]));

    eprintln!("=== SUCCESS: Full real Content proto roundtrip works! ===");
    eprintln!("  body: {:?}", decoded_dm.body);
    eprintln!("  timestamp: {:?}", decoded_dm.timestamp);
    eprintln!("  profile_key len: {:?}", decoded_dm.profile_key.as_ref().map(|k| k.len()));
}
