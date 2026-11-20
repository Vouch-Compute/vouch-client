//! Node protocol frames: any bytes into the node's inbound decoder (protobuf + seq rules). Must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let mut inb = pool_proto::frame::Inbound::new();
    let _ = inb.decode(data);
    let _ = pool_proto::pb::ServerMessage::decode(data);
    let _ = pool_proto::pb::NodeMessage::decode(data);
    // a stream of frames split at arbitrary points
    for chunk in data.chunks(64) {
        let _ = inb.decode(chunk);
    }
});
