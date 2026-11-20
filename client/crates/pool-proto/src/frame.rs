//! WebSocket framing rules: one protobuf message per binary frame,
//! at most 1 MiB, and `seq` starting at 1 and increasing by exactly 1 in each direction.
//! A gap or a repeat (replayed frame) is a protocol error that ends the session.

use prost::Message;

use crate::pb::{node_message, server_message, NodeMessage, ServerMessage};
use crate::Error;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Outbound sequencing for NodeMessage frames.
#[derive(Debug)]
pub struct Outbound {
    next: u64,
}

impl Default for Outbound {
    fn default() -> Self {
        Self::new()
    }
}

impl Outbound {
    pub fn new() -> Self {
        Self { next: 1 }
    }
    pub fn encode(&mut self, body: node_message::Body) -> Vec<u8> {
        let seq = self.next;
        self.next += 1;
        NodeMessage { seq, body: Some(body) }.encode_to_vec()
    }
}

/// Inbound validation for ServerMessage frames.
#[derive(Debug)]
pub struct Inbound {
    expected: u64,
}

impl Default for Inbound {
    fn default() -> Self {
        Self::new()
    }
}

impl Inbound {
    pub fn new() -> Self {
        Self { expected: 1 }
    }
    /// Decode one binary frame. Errors: oversize, undecodable, seq gap or repeat.
    ///
    /// Node protocol 1.2.0: a `ServerMessage` whose `body` is a variant this node does not know (a newer
    /// server's addition; protobuf skips the unknown oneof field) decodes as `Ok((seq, None))`. The frame still counts
    /// for sequencing, and the caller ignores it instead of dropping the session.
    pub fn decode(&mut self, frame: &[u8]) -> Result<(u64, Option<server_message::Body>), Error> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(Error::Protocol("frame over 1 MiB"));
        }
        let msg = ServerMessage::decode(frame).map_err(|_| Error::Protocol("undecodable frame"))?;
        if msg.seq != self.expected {
            return Err(Error::Protocol(if msg.seq < self.expected {
                "seq repeat (replay)"
            } else {
                "seq gap"
            }));
        }
        self.expected += 1;
        Ok((msg.seq, msg.body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::*;

    fn server(seq: u64, body: server_message::Body) -> Vec<u8> {
        ServerMessage { seq, body: Some(body) }.encode_to_vec()
    }

    #[test]
    fn roundtrip_and_seq_rules() {
        let mut inb = Inbound::new();
        let ch = server_message::Body::Challenge(Challenge {
            nonce: vec![7; 32],
            server_time_ms: 5,
            protocol_version: crate::PROTOCOL_VERSION.into(),
        });
        let f1 = server(1, ch.clone());
        assert_eq!(inb.decode(&f1).unwrap(), (1, Some(ch.clone())));
        // replay of seq 1
        assert_eq!(inb.decode(&f1), Err(Error::Protocol("seq repeat (replay)")));
        let mut inb = Inbound::new();
        inb.decode(&f1).unwrap();
        assert_eq!(inb.decode(&server(3, ch.clone())), Err(Error::Protocol("seq gap")));
        // starting at 0 is invalid
        assert!(Inbound::new().decode(&server(0, ch)).is_err());
    }

    #[test]
    fn outbound_seq_starts_at_one() {
        let mut out = Outbound::new();
        let a = out.encode(node_message::Body::Accept(Accept { job_id: "x".into() }));
        let b = out.encode(node_message::Body::Accept(Accept { job_id: "y".into() }));
        let a = NodeMessage::decode(&a[..]).unwrap();
        let b = NodeMessage::decode(&b[..]).unwrap();
        assert_eq!((a.seq, b.seq), (1, 2));
    }

    #[test]
    fn oversize_and_garbage_frames_rejected() {
        assert!(Inbound::new().decode(&vec![0u8; MAX_FRAME_BYTES + 1]).is_err());
        assert!(Inbound::new().decode(&[0xff, 0xff, 0xff]).is_err());
        // a body this node does not know (or none) is not an error: it is ignored, and still sequenced (1.2.0)
        let empty = ServerMessage { seq: 1, body: None }.encode_to_vec();
        let mut inb = Inbound::new();
        assert_eq!(inb.decode(&empty), Ok((1, None)));
        assert_eq!(inb.decode(&empty), Err(Error::Protocol("seq repeat (replay)")));
    }

    /// A field number no version of the contract defines yet (a future server message) inside `ServerMessage.body`.
    fn future_variant_frame(seq: u64) -> Vec<u8> {
        let mut v = ServerMessage { seq, body: None }.encode_to_vec();
        // field 99, wire type 2 (length-delimited), 3-byte payload
        prost::encoding::encode_key(99, prost::encoding::WireType::LengthDelimited, &mut v);
        prost::encoding::encode_varint(3, &mut v);
        v.extend_from_slice(&[0x08, 0x01, 0x10]);
        v
    }

    /// The numeric constants match the generated enums (fails to compile or run if `node.proto` renumbers them).
    #[test]
    fn notice_and_governor_numbers_match_node_proto() {
        let kinds = [
            (crate::account_notice::PAUSED_BY_USER, "PAUSED_BY_USER"),
            (crate::account_notice::PAUSED_BY_TALLY, "PAUSED_BY_TALLY"),
            (crate::account_notice::RESUMED, "RESUMED"),
            (crate::account_notice::RECOVERY_IN_PROGRESS, "RECOVERY_IN_PROGRESS"),
            (crate::account_notice::REVERIFY_REQUIRED, "REVERIFY_REQUIRED"),
        ];
        for (n, name) in kinds {
            assert!(AccountNoticeKind::try_from(n).unwrap().as_str_name().ends_with(name), "{n} {name}");
        }
        let states = [
            (crate::governor_state::RUNNING, "RUNNING"),
            (crate::governor_state::IDLE_WAIT, "IDLE_WAIT"),
            (crate::governor_state::THERMAL, "THERMAL"),
            (crate::governor_state::BATTERY, "BATTERY"),
            (crate::governor_state::SCHEDULE, "SCHEDULE"),
            (crate::governor_state::USER_PAUSED, "USER_PAUSED"),
        ];
        for (n, name) in states {
            assert!(GovernorState::try_from(n).unwrap().as_str_name().ends_with(name), "{n} {name}");
        }
    }

    #[test]
    fn unknown_server_variants_are_ignored_and_sequenced() {
        let mut inb = Inbound::new();
        assert_eq!(inb.decode(&future_variant_frame(1)), Ok((1, None)));
        let notice = server_message::Body::AccountNotice(AccountNotice { kind: crate::account_notice::PAUSED_BY_USER });
        assert_eq!(inb.decode(&server(2, notice.clone())), Ok((2, Some(notice))));
        assert_eq!(inb.decode(&future_variant_frame(4)), Err(Error::Protocol("seq gap")));
    }

    /// 1.2.0 node against a 1.1.0 server and the reverse, with the 1.1.0 types generated from
    /// `tests/data/node-1.1.0.proto`.
    #[test]
    fn protocol_1_1_and_1_2_interoperate() {
        use crate::pb_v110 as old;
        // a 1.2.0 node's Heartbeat with telemetry: a 1.1.0 server reads the 1.1.0 fields and skips the rest
        let hb = Heartbeat {
            load: 1.0,
            temp_ok: true,
            on_ac: true,
            accepting_work: true,
            cached_models: vec![CachedModel { model_id: "m".into(), model_hash: vec![7; 32] }],
            temp_c: Some(71),
            gpu_util_pct: Some(93),
            power_limit_pct: Some(80),
            governor_state: Some(crate::governor_state::RUNNING),
        };
        let bytes = Outbound::new().encode(node_message::Body::Heartbeat(hb.clone()));
        let m = old::NodeMessage::decode(&bytes[..]).unwrap();
        let Some(old::node_message::Body::Heartbeat(o)) = m.body else { panic!("{m:?}") };
        assert_eq!((o.load, o.temp_ok, o.on_ac, o.accepting_work), (1.0, true, true, true));
        assert_eq!(o.cached_models.len(), 1);
        // a 1.1.0 node's Heartbeat (no telemetry) is a valid 1.2.0 Heartbeat with the telemetry absent
        let o = old::Heartbeat { load: 0.0, temp_ok: true, on_ac: false, accepting_work: false, cached_models: vec![] };
        let n = Heartbeat::decode(&o.encode_to_vec()[..]).unwrap();
        assert_eq!((n.temp_c, n.gpu_util_pct, n.power_limit_pct, n.governor_state), (None, None, None, None));
        // a 1.1.0 server's messages decode on a 1.2.0 node unchanged
        let ch = old::ServerMessage {
            seq: 1,
            body: Some(old::server_message::Body::Welcome(old::Welcome {
                session_id: "s".into(),
                session_expires_ms: 9,
                heartbeat_interval_s: 30,
                server_time_ms: 1,
            })),
        };
        let mut inb = Inbound::new();
        assert!(matches!(inb.decode(&ch.encode_to_vec()), Ok((1, Some(server_message::Body::Welcome(_))))));
        // a 1.2.0 server's AccountNotice is an unknown oneof variant for a 1.1.0 decoder: body None, never a crash
        let notice = server(2, server_message::Body::AccountNotice(AccountNotice { kind: crate::account_notice::RESUMED }));
        let seen_by_old = old::ServerMessage::decode(&notice[..]).unwrap();
        assert_eq!((seen_by_old.seq, seen_by_old.body), (2, None));
    }

    #[test]
    fn every_message_roundtrips() {
        let mut out = Outbound::new();
        let bodies = vec![
            node_message::Body::Hello(Hello {
                protocol_version: crate::PROTOCOL_VERSION.into(),
                device_id: "d".into(),
                device_key_id: "k".into(),
                agent_version: "0.1.0".into(),
                os: "windows".into(),
                arch: "x86_64".into(),
                cached_models: vec![CachedModel { model_id: "m".into(), model_hash: vec![3; 32] }],
                hello_sig: vec![1, 2, 3],
            }),
            node_message::Body::Decline(Decline { job_id: "j".into(), reason: DeclineReason::UserActive as i32 }),
            node_message::Body::Result(Result { job_id: "j".into(), lease_id: "l".into(), result_sig: vec![9] }),
            node_message::Body::Abandon(Abandon {
                job_id: "j".into(),
                lease_id: "l".into(),
                reason: AbandonReason::Preempted as i32,
            }),
            node_message::Body::Heartbeat(Heartbeat {
                load: 0.5,
                temp_ok: true,
                on_ac: true,
                accepting_work: false,
                cached_models: vec![],
                ..Default::default()
            }),
        ];
        for (i, b) in bodies.into_iter().enumerate() {
            let m = NodeMessage::decode(&out.encode(b.clone())[..]).unwrap();
            assert_eq!(m.seq, i as u64 + 1);
            assert_eq!(m.body, Some(b));
        }
    }

    /// Schema test: `Offer` carries exactly {job_id, model_id, model_hash, est_units, deadline_ms}.
    /// Encoding an Offer with every field set must produce exactly tags 1..=5 and nothing else.
    #[test]
    fn offer_has_exactly_the_five_vt2_fields() {
        let o = Offer { job_id: "j".into(), model_id: "m".into(), model_hash: vec![1; 32], est_units: 9, deadline_ms: 10 };
        let bytes = o.encode_to_vec();
        let mut tags = vec![];
        let mut buf = &bytes[..];
        while !buf.is_empty() {
            let key = prost::encoding::decode_varint(&mut buf).unwrap();
            tags.push((key >> 3) as u32);
            match key & 7 {
                0 => {
                    prost::encoding::decode_varint(&mut buf).unwrap();
                }
                2 => {
                    let len = prost::encoding::decode_varint(&mut buf).unwrap() as usize;
                    buf = &buf[len..];
                }
                _ => panic!("unexpected wire type"),
            }
        }
        assert_eq!(tags, vec![1, 2, 3, 4, 5]);
        // the generated struct has exactly these five fields (exhaustive destructure fails to compile otherwise)
        let Offer { job_id: _, model_id: _, model_hash: _, est_units: _, deadline_ms: _ } = o;
    }
}
