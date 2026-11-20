//! What the app may show of the server's `DeviceView` (the published display field limits).
//!
//! The agent passes the server's object through a closed allow-list and nothing else: the reliability tier, its benefits and
//! the operational hints come from the server as they are. The app never computes, infers or caches a tier (the agent does
//! not store this object; the UI does not keep it in browser storage). Unknown fields, unknown hint words and anything
//! that looks like a score or a speed are dropped, so a server mistake cannot leak verification data into the app.

use serde_json::{json, Map, Value};

/// `DeviceView` fields the app shows (the API's `DeviceView` schema, closed).
const FIELDS: &[&str] = &[
    "device_id", "name", "os", "arch", "hw_summary", "status", "tier", "benchmark_date", "eligible_models", "last_seen_day", "trust_ceiling",
    "connection", "activity", "paused_by",
];

pub const RELIABILITY_TIERS: &[&str] = &["probation", "premium", "stable", "less_stable", "unpredictable"];
pub const QUEUE_PRIORITIES: &[&str] = &["standard", "higher", "highest"];
/// The fixed list of operational hints.
pub const IMPROVE_HINTS: &[&str] =
    &["keep_regular_hours", "avoid_disconnects", "finish_accepted_jobs", "build_tenure", "verify_identity", "use_hardware_key"];

fn one_of(v: Option<&Value>, allowed: &[&str]) -> Option<Value> {
    let s = v?.as_str()?;
    allowed.contains(&s).then(|| Value::String(s.to_string()))
}

/// `DeviceView.reliability` as the server sent it, restricted to `{tier, since_day, benefits{queue_priority, bonus_pct},
/// improve[]}`; `None` when the server sent none or an unknown tier.
pub fn reliability_for_app(r: &Value) -> Option<Value> {
    let tier = one_of(r.get("tier"), RELIABILITY_TIERS)?;
    let since_day = r.get("since_day").and_then(Value::as_str).filter(|d| d.len() == 10).map(str::to_string);
    let b = r.get("benefits");
    let bonus = b.and_then(|b| b.get("bonus_pct")).and_then(Value::as_f64).filter(|x| x.is_finite() && (0.0..=20.0).contains(x));
    let improve: Vec<Value> = r
        .get("improve")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|h| one_of(Some(h), IMPROVE_HINTS)).collect())
        .unwrap_or_default();
    Some(json!({
        "tier": tier,
        "since_day": since_day,
        "benefits": {
            "queue_priority": one_of(b.and_then(|b| b.get("queue_priority")), QUEUE_PRIORITIES),
            "bonus_pct": bonus,
        },
        "improve": improve,
    }))
}

/// the server's `DeviceView` -> what the app shows.
pub fn for_app(v: &Value) -> Value {
    let mut out = Map::new();
    for f in FIELDS {
        if let Some(x) = v.get(*f) {
            out.insert((*f).to_string(), x.clone());
        }
    }
    if let Some(r) = v.get("reliability").and_then(reliability_for_app) {
        out.insert("reliability".into(), r);
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_vaults_reliability_object_and_nothing_else() {
        let vault = json!({
            "device_id": "d", "name": "Gaming PC", "os": "windows", "arch": "x86_64", "hw_summary": "RTX 4070", "status": "active",
            "tier": "established", "benchmark_date": "2026-11-01", "eligible_models": ["m"], "last_seen_day": "2026-11-18",
            "trust_ceiling": "full", "connection": "online", "activity": "idle", "paused_by": null,
            "reliability": { "tier": "stable", "since_day": "2026-11-12", "benefits": { "queue_priority": "higher", "bonus_pct": 5 },
                "improve": ["keep_regular_hours", "canary_pass_rate", "avoid_disconnects"], "score": 0.93, "threshold": 0.9 },
            "canary_stats": { "pass": 10 }, "latency_p50_ms": 1200
        });
        let app = for_app(&vault);
        assert_eq!(app["reliability"], json!({ "tier": "stable", "since_day": "2026-11-12",
            "benefits": { "queue_priority": "higher", "bonus_pct": 5.0 }, "improve": ["keep_regular_hours", "avoid_disconnects"] }));
        assert_eq!(app["connection"], "online");
        let text = app.to_string();
        for banned in ["score", "threshold", "canary", "latency", "spot", "speed", "0.93"] {
            assert!(!text.contains(banned), "{banned} leaked: {text}");
        }
        // no reliability object, or an unknown tier: nothing is shown (and nothing is made up)
        assert!(for_app(&json!({"device_id": "d"})).get("reliability").is_none());
        assert!(for_app(&json!({"reliability": {"tier": "gold"}})).get("reliability").is_none());
    }
}
