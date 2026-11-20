//! Money as the server sends it (contract 2.0.0): every amount is a `UsdAmount` decimal string with at most
//! 9 fractional digits (servers emit exactly 9, e.g. `"12.345678901"`). It is parsed into integer **nano-USD**
//! and never into a float. Rates are per quantum (`quantum_units` = 3600 audio seconds, 1,000,000 tokens,
//! 1,000 images) with `*_usd_per_quantum` amounts.
//!
//! The agent parses the server's estimate and earnings responses into these types before handing them to the app, so a
//! malformed amount (a float, an exponent, 10 fractional digits) is refused here instead of being shown. Display
//! strings are made here with integer arithmetic; the app only renders them.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const NANOS_PER_USD: i128 = 1_000_000_000;

/// An exact USD amount in nano-USD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct UsdAmount(pub i128);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a UsdAmount decimal string: {0:?}")]
pub struct BadAmount(pub String);

impl UsdAmount {
    pub fn from_nanos(n: i128) -> Self {
        Self(n)
    }
    pub fn nanos(self) -> i128 {
        self.0
    }

    /// `^-?(0|[1-9][0-9]*)(\.[0-9]{1,9})?$` (openapi `UsdAmount`), exactly.
    pub fn parse(s: &str) -> Result<Self, BadAmount> {
        let bad = || BadAmount(s.chars().take(40).collect());
        let (neg, body) = match s.strip_prefix('-') {
            Some(b) => (true, b),
            None => (false, s),
        };
        let (int, frac) = match body.split_once('.') {
            Some((i, f)) => (i, Some(f)),
            None => (body, None),
        };
        let int_ok = int == "0" || (!int.is_empty() && !int.starts_with('0') && int.bytes().all(|b| b.is_ascii_digit()));
        if !int_ok || int.len() > 18 {
            return Err(bad());
        }
        let mut nanos: i128 = int.parse::<i128>().map_err(|_| bad())? * NANOS_PER_USD;
        if let Some(f) = frac {
            if f.is_empty() || f.len() > 9 || !f.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            let scaled = f.parse::<i128>().map_err(|_| bad())? * 10i128.pow(9 - f.len() as u32);
            nanos += scaled;
        }
        Ok(Self(if neg { -nanos } else { nanos }))
    }

    /// Canonical form with exactly 9 fractional digits, as the server emits it.
    pub fn to_canonical(self) -> String {
        let sign = if self.0 < 0 { "-" } else { "" };
        let a = self.0.unsigned_abs();
        format!("{sign}{}.{:09}", a / NANOS_PER_USD as u128, a % NANOS_PER_USD as u128)
    }

    /// Display for people: `$12.35`; amounts under one cent keep 4 decimals (`$0.0042`) so small numbers are not
    /// shown as zero. Rounds half away from zero, in integers.
    pub fn display(self) -> String {
        let a = self.0.unsigned_abs();
        let sign = if self.0 < 0 { "-" } else { "" };
        let cent = (NANOS_PER_USD / 100) as u128;
        if a != 0 && a < cent {
            let unit = 100_000u128; // 1e-4 USD
            let q = (a + unit / 2) / unit;
            return format!("{sign}${}.{:04}", q / 10_000, q % 10_000);
        }
        let q = (a + cent / 2) / cent;
        format!("{sign}${}.{:02}", group(q / 100), q % 100)
    }
}

fn group(mut n: u128) -> String {
    let mut parts = Vec::new();
    loop {
        if n < 1000 {
            parts.push(n.to_string());
            break;
        }
        parts.push(format!("{:03}", n % 1000));
        n /= 1000;
    }
    parts.reverse();
    parts.join(",")
}

impl Serialize for UsdAmount {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_canonical())
    }
}

impl<'de> Deserialize<'de> for UsdAmount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // A JSON number here is a contract violation (floats are never money): only strings are accepted.
        let s = String::deserialize(d)?;
        UsdAmount::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A rate per quantum (`/v1/rate-card`, `/v1/pricing`): `amount` USD per `quantum_units` units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsdPerQuantum {
    pub amount: UsdAmount,
    pub quantum_units: u64,
}

impl UsdPerQuantum {
    /// "$0.05 per audio hour", "$0.006 per 1M tokens", "$0.10 per 1,000 images".
    pub fn display(&self, unit_type: &str) -> String {
        let per = match (unit_type, self.quantum_units) {
            ("audio_sec", 3600) => "audio hour".to_string(),
            ("token", 1_000_000) => "1M tokens".to_string(),
            ("image", 1000) => "1,000 images".to_string(),
            (u, q) => format!("{} {u}", group(u128::from(q))),
        };
        // rates are small: keep up to 6 significant decimals without float rounding
        let a = self.amount.0.unsigned_abs();
        let whole = a / NANOS_PER_USD as u128;
        let mut frac = format!("{:09}", a % NANOS_PER_USD as u128);
        while frac.len() > 2 && frac.ends_with('0') {
            frac.pop();
        }
        format!("${whole}.{frac} per {per}")
    }

    /// Contributor value for `units_milli` at this rate, in nano-USD, floored.
    pub fn value_floor(&self, units_milli: u64) -> UsdAmount {
        let num = i128::from(units_milli) * self.amount.0;
        UsdAmount(num.div_euclid(i128::from(self.quantum_units) * 1000))
    }
}

// ------------------------------------------------------------------ the server responses the app shows

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EstimateBase {
    pub low_usd: UsdAmount,
    pub high_usd: UsdAmount,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EstimateAssumptions {
    pub utilization: f64,
    pub hours_per_day: f64,
    pub electricity_usd_per_kwh: f64,
    pub avg_watts: f64,
    pub electricity_cost_usd: UsdAmount,
}

/// `GET /v1/estimate?device_id=` (2.0.0). Always a range; `base` is the pay for the work itself, the multiplier
/// (a temporary launch bonus) is shown separately, electricity is already subtracted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Estimate {
    pub low_usd: UsdAmount,
    pub high_usd: UsdAmount,
    pub period: String,
    pub base: EstimateBase,
    pub multiplier: f64,
    pub multiplier_end: Option<String>,
    pub assumptions: EstimateAssumptions,
    pub rate_card_version: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EarningsTotals {
    pub pending: UsdAmount,
    pub in_escrow: UsdAmount,
    pub in_review: UsdAmount,
    pub releasable: UsdAmount,
    pub sent: UsdAmount,
    pub clawed_back: UsdAmount,
}

/// `GET /v1/earnings/summary` (2.0.0). Unknown extra fields are passed through.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EarningsSummary {
    pub as_of: String,
    pub totals: EarningsTotals,
    pub this_week_verified_usd: UsdAmount,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// Parse the server's estimate and add display strings (`display.*`) computed in integers. The app renders those
/// strings and never does arithmetic on money.
pub fn estimate_for_app(v: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let e: Estimate = serde_json::from_value(v).map_err(|e| anyhow::anyhow!("estimate from vault is malformed: {e}"))?;
    let mut out = serde_json::to_value(&e)?;
    out["display"] = serde_json::json!({
        "range": format!("{} – {}", e.low_usd.display(), e.high_usd.display()),
        "base_range": format!("{} – {}", e.base.low_usd.display(), e.base.high_usd.display()),
        "electricity_cost": e.assumptions.electricity_cost_usd.display(),
    });
    Ok(out)
}

/// Parse the server's earnings summary and add display strings.
pub fn earnings_for_app(v: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let s: EarningsSummary = serde_json::from_value(v).map_err(|e| anyhow::anyhow!("earnings from vault are malformed: {e}"))?;
    let t = &s.totals;
    let mut out = serde_json::to_value(&s)?;
    out["display"] = serde_json::json!({
        "pending": t.pending.display(),
        "in_escrow": t.in_escrow.display(),
        "in_review": t.in_review.display(),
        "releasable": t.releasable.display(),
        "sent": t.sent.display(),
        "clawed_back": t.clawed_back.display(),
        "this_week_verified": s.this_week_verified_usd.display(),
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_decimal_strings_only() {
        assert_eq!(UsdAmount::parse("12.345678901").unwrap().nanos(), 12_345_678_901);
        assert_eq!(UsdAmount::parse("0.000000001").unwrap().nanos(), 1);
        assert_eq!(UsdAmount::parse("10").unwrap().nanos(), 10_000_000_000);
        assert_eq!(UsdAmount::parse("1.25").unwrap().nanos(), 1_250_000_000);
        assert_eq!(UsdAmount::parse("-0.5").unwrap().nanos(), -500_000_000);
        // 0.1 + 0.2 is exact here (it is not with floats)
        let s = UsdAmount::parse("0.1").unwrap().nanos() + UsdAmount::parse("0.2").unwrap().nanos();
        assert_eq!(UsdAmount(s).to_canonical(), "0.300000000");
        for bad in ["", "-", ".5", "1.", "01", "1.0000000001", "1e3", "1.5e-3", " 1", "1 ", "+1", "0x10", "1,5", "NaN", "∞"] {
            assert!(UsdAmount::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(UsdAmount::parse("1234567.000000000").unwrap().to_canonical(), "1234567.000000000");
        assert_eq!(UsdAmount(-1).to_canonical(), "-0.000000001");
    }

    #[test]
    fn json_numbers_are_refused() {
        assert!(serde_json::from_str::<UsdAmount>("12.5").is_err());
        assert!(serde_json::from_str::<UsdAmount>("12500000").is_err());
        assert_eq!(serde_json::from_str::<UsdAmount>("\"12.500000000\"").unwrap().nanos(), 12_500_000_000);
        assert_eq!(serde_json::to_string(&UsdAmount(5)).unwrap(), "\"0.000000005\"");
    }

    #[test]
    fn display_rounds_in_integers() {
        let d = |s: &str| UsdAmount::parse(s).unwrap().display();
        assert_eq!(d("12.345678901"), "$12.35");
        assert_eq!(d("12.344999999"), "$12.34");
        assert_eq!(d("0.004200000"), "$0.0042");
        assert_eq!(d("0.000049999"), "$0.0000");
        assert_eq!(d("0.009999999"), "$0.0100");
        assert_eq!(d("0"), "$0.00");
        assert_eq!(d("1234567.995"), "$1,234,568.00");
        assert_eq!(d("-4.100000000"), "-$4.10");
    }

    #[test]
    fn per_quantum_rates() {
        let r = UsdPerQuantum { amount: UsdAmount::parse("0.050000000").unwrap(), quantum_units: 3600 };
        assert_eq!(r.display("audio_sec"), "$0.05 per audio hour");
        // 90 s of audio at $0.05/h = 0.00125 USD = 1,250,000 nanos (exact)
        assert_eq!(r.value_floor(90_000).nanos(), 1_250_000);
        // one second: 50,000,000 / 3600 = 13,888.88.. nanos -> floor
        assert_eq!(r.value_floor(1000).nanos(), 13_888);
        let t = UsdPerQuantum { amount: UsdAmount::parse("0.006").unwrap(), quantum_units: 1_000_000 };
        assert_eq!(t.display("token"), "$0.006 per 1M tokens");
        // 500 tokens at $0.006/1M = 3,000 nanos (micro-USD integers would have floored this)
        assert_eq!(t.value_floor(500_000).nanos(), 3_000);
    }

    #[test]
    fn estimate_and_earnings_2_0_0_shapes() {
        let est = serde_json::json!({
            "low_usd": "9.000000000", "high_usd": "24.000000000", "period": "month",
            "base": {"low_usd": "3.500000000", "high_usd": "9.000000000"},
            "multiplier": 3, "multiplier_end": "2027-03-01T00:00:00Z",
            "assumptions": {"utilization": 0.35, "hours_per_day": 14, "electricity_usd_per_kwh": 0.15,
                            "avg_watts": 180, "electricity_cost_usd": "4.100000000"},
            "rate_card_version": 1
        });
        let out = estimate_for_app(est.clone()).unwrap();
        assert_eq!(out["display"]["range"], "$9.00 – $24.00");
        assert_eq!(out["display"]["base_range"], "$3.50 – $9.00");
        assert_eq!(out["display"]["electricity_cost"], "$4.10");
        assert_eq!(out["low_usd"], "9.000000000");
        // the 1.x micro-USD integers are refused, not misread
        let mut old = est.clone();
        old["low_usd"] = serde_json::json!(9_000_000);
        assert!(estimate_for_app(old).is_err());
        let old = serde_json::json!({"low_usd_micros": 9_000_000, "high_usd_micros": 24_000_000});
        assert!(estimate_for_app(old).is_err());

        let earn = serde_json::json!({
            "as_of": "2026-11-17",
            "totals": {"pending": "2.310000000", "in_escrow": "6.870000000", "in_review": "0.120000000",
                       "releasable": "0.000000000", "sent": "0.000000000", "clawed_back": "0.000000000"},
            "this_week_verified_usd": "3.100000000",
            "probation": {"active": true, "escrow_days": 21, "ends_on": "2026-12-05"},
            "alerts": []
        });
        let out = earnings_for_app(earn).unwrap();
        assert_eq!(out["display"]["in_escrow"], "$6.87");
        assert_eq!(out["display"]["this_week_verified"], "$3.10");
        assert_eq!(out["probation"]["escrow_days"], 21);
        assert_eq!(out["totals"]["pending"], "2.310000000");
    }
}
