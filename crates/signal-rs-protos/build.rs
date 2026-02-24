use std::io::Result;

fn main() -> Result<()> {
    let proto_files = &[
        "proto/SignalService.proto",
        "proto/SubProtocol.proto",
        "proto/Groups.proto",
        "proto/Provisioning.proto",
        "proto/StorageService.proto",
        "proto/WireMessages.proto",
        "proto/SealedSender.proto",
    ];

    let includes = &["proto/"];

    // Re-run if any proto file changes
    for proto in proto_files {
        println!("cargo:rerun-if-changed={proto}");
    }

    let mut config = prost_build::Config::new();

    // Add serde derives on key message types for JSON serialization support.
    // We apply them broadly to the package so all generated structs get them.
    config.type_attribute(
        ".signalservice",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );
    config.type_attribute(
        ".signal.proto.wire",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );
    config.type_attribute(
        ".signal.proto.sealed_sender",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );

    config.compile_protos(proto_files, includes)?;

    Ok(())
}
