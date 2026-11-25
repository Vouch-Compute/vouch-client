//! The account server's public API used by the agent.
//!
//! Sign-in uses the RFC 8628 device authorization grant: the app shows a code, the user signs in on the
//! web with the email magic link plus TOTP/passkey (MFA is mandatory) and approves the device. The
//! resulting token is read-only plus enrollment (`earnings:read devices:read devices:enroll`),
//! so the desktop app has no wallet-write path: it only displays `GET /v1/wallets`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Requested scopes. the server grants device-link tokens `earnings:read devices:read devices:enroll`
/// Enrollment only, no wallet, KYC or payout scope.
pub const DEVICE_SCOPES: &str = "earnings:read devices:read devices:enroll";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
}

#[derive(Debug)]
pub enum TokenPoll {
    Pending,
    SlowDown,
    Denied,
    Expired,
    Ok(Tokens),
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollmentChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub expires_at: String,
    /// 2.1.0: TPM2_MakeCredential output for the `tpm2` v2 blob (requested with `{tpm: {ek_public, aik_public}}`).
    #[serde(default)]
    pub tpm_activation: Option<TpmActivationB64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpmActivationB64 {
    pub credential_blob: String,
    pub encrypted_secret: String,
}

/// A server error answer: HTTP status, `error.code` and `error.details` (the app maps the codes to plain words).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("vault {status}: {code}")]
pub struct VaultError {
    pub status: u16,
    pub code: String,
    pub details: Value,
    /// The server's own words (`error.message`, or OAuth's `error_description`): logged, never shown (English).
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceRegistered {
    pub device_id: String,
    pub device_key_id: String,
    pub tier: String,
    pub trust_ceiling: String,
}

/// Self-asserted device details sent with `POST /oauth2/device_authorization`.
/// Limits from the API schema: `device_name` <= 64, `os` / `arch` / `agent_version` <= 32 characters.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeviceLinkInfo {
    pub device_name: String,
    pub os: String,
    pub arch: String,
    pub agent_version: String,
}

fn clip(s: &str, max_chars: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max_chars).collect::<String>().trim().to_string()
}

impl DeviceLinkInfo {
    pub fn this_device() -> Self {
        Self {
            device_name: crate::platform::device_name(),
            os: crate::platform::os_name().into(),
            arch: crate::platform::arch().into(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    /// Form fields, clipped to the contract's limits; empty values are left out (all four are optional).
    pub fn form_fields(&self) -> Vec<(&'static str, String)> {
        [
            ("device_name", clip(&self.device_name, 64)),
            ("os", clip(&self.os, 32)),
            ("arch", clip(&self.arch, 32)),
            ("agent_version", clip(&self.agent_version, 32)),
        ]
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .collect()
    }
}

#[derive(Clone)]
pub struct VaultClient {
    pub base: String,
    pub client_id: String,
    http: reqwest::Client,
}

async fn json_or_err(resp: reqwest::Response) -> anyhow::Result<Value> {
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if status.is_success() {
        Ok(body)
    } else {
        let code = body.pointer("/error/code").or_else(|| body.get("error")).and_then(|v| v.as_str()).unwrap_or("error");
        let message = body.pointer("/error/message").or_else(|| body.get("error_description")).and_then(|v| v.as_str()).unwrap_or("");
        let message: String = message.chars().filter(|c| !c.is_control()).take(200).collect();
        tracing::info!("vault answered {status} {code}: {message}");
        Err(VaultError {
            status: status.as_u16(),
            code: code.to_string(),
            details: body.pointer("/error/details").cloned().unwrap_or(Value::Null),
            message,
        }
        .into())
    }
}

/// `204`/`202` with no body.
async fn empty_or_err(resp: reqwest::Response) -> anyhow::Result<()> {
    if resp.status().is_success() {
        return Ok(());
    }
    json_or_err(resp).await.map(|_| ())
}

impl VaultClient {
    pub fn new(base: &str, client_id: &str, http: reqwest::Client) -> Self {
        Self { base: base.trim_end_matches('/').to_string(), client_id: client_id.into(), http }
    }

    /// RFC 8628 start. `device` is shown to the user on face's `/app/link` as "reported by the app" before they
    /// confirm, so a code relayed from someone else's machine stands out.
    pub async fn device_authorization(&self, device: &DeviceLinkInfo) -> anyhow::Result<DeviceCode> {
        let mut form = vec![("client_id", self.client_id.clone()), ("scope", DEVICE_SCOPES.to_string())];
        form.extend(device.form_fields());
        let v = json_or_err(self.http.post(format!("{}/oauth2/device_authorization", self.base)).form(&form).send().await?).await?;
        Ok(serde_json::from_value(v)?)
    }

    pub async fn poll_token(&self, device_code: &str) -> anyhow::Result<TokenPoll> {
        let resp = self
            .http
            .post(format!("{}/oauth2/token", self.base))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", self.client_id.as_str()),
            ])
            .send()
            .await?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(TokenPoll::Ok(serde_json::from_value(body)?));
        }
        let err = body.get("error").and_then(|v| v.as_str()).or_else(|| body.pointer("/error/code").and_then(|v| v.as_str()));
        Ok(match err {
            Some("authorization_pending") => TokenPoll::Pending,
            Some("slow_down") => TokenPoll::SlowDown,
            Some("access_denied") => TokenPoll::Denied,
            Some("expired_token") => TokenPoll::Expired,
            _ => anyhow::bail!("token endpoint {status}"),
        })
    }

    pub async fn refresh(&self, refresh_token: &str) -> anyhow::Result<Tokens> {
        let v = json_or_err(
            self.http
                .post(format!("{}/oauth2/token", self.base))
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                    ("client_id", self.client_id.as_str()),
                ])
                .send()
                .await?,
        )
        .await?;
        Ok(serde_json::from_value(v)?)
    }

    /// `tpm`: `(ek_public, aik_public)` TPM2B_PUBLIC bytes, for a `tpm_activation` credential.
    pub async fn enrollment_challenge(&self, token: &str, tpm: Option<(&[u8], &[u8])>) -> anyhow::Result<EnrollmentChallenge> {
        let mut req = self
            .http
            .post(format!("{}/v1/devices/enrollment-challenges", self.base))
            .bearer_auth(token)
            .header("Idempotency-Key", uuid::Uuid::new_v4().to_string());
        if let Some((ek, aik)) = tpm {
            req = req.json(&serde_json::json!({ "tpm": { "ek_public": pool_proto::keys::b64(ek), "aik_public": pool_proto::keys::b64(aik) } }));
        }
        let v = json_or_err(req.send().await?).await?;
        Ok(serde_json::from_value(v)?)
    }

    /// `POST /v1/devices/{id}/control` with a COSE `DeviceControl` (no bearer: the device key is the credential).
    pub async fn device_control(&self, device_id: &str, control_cose: &[u8]) -> anyhow::Result<()> {
        empty_or_err(
            self.http
                .post(format!("{}/v1/devices/{device_id}/control", self.base))
                .json(&serde_json::json!({ "control": pool_proto::keys::b64(control_cose) }))
                .send()
                .await?,
        )
        .await
    }

    /// `POST /v1/devices/{id}/hw-ids` (weekly; the device key's COSE signature is the credential).
    pub async fn report_hw_ids(&self, device_id: &str, hw_ids_b64: &str) -> anyhow::Result<()> {
        empty_or_err(
            self.http
                .post(format!("{}/v1/devices/{device_id}/hw-ids", self.base))
                .json(&serde_json::json!({ "hw_ids": hw_ids_b64 }))
                .send()
                .await?,
        )
        .await
    }

    /// `POST /v1/auth/recovery-cases/{case_id}/device-proof` (authenticated by the `RecoveryProof` signature).
    pub async fn recovery_device_proof(&self, case_id: &str, device_id: &str, proof_cose: &[u8]) -> anyhow::Result<()> {
        empty_or_err(
            self.http
                .post(format!("{}/v1/auth/recovery-cases/{case_id}/device-proof", self.base))
                .json(&serde_json::json!({ "device_id": device_id, "proof": pool_proto::keys::b64(proof_cose) }))
                .send()
                .await?,
        )
        .await
    }

    /// `POST /v1/devices/{id}/key-rotations` -> the new `device_key_id`.
    pub async fn rotate_key(&self, token: &str, device_id: &str, body: &Value) -> anyhow::Result<String> {
        let v = json_or_err(
            self.http
                .post(format!("{}/v1/devices/{device_id}/key-rotations", self.base))
                .bearer_auth(token)
                .header("Idempotency-Key", uuid::Uuid::new_v4().to_string())
                .json(body)
                .send()
                .await?,
        )
        .await?;
        v.get("device_key_id").and_then(Value::as_str).map(str::to_string).ok_or_else(|| anyhow::anyhow!("no device_key_id"))
    }

    pub async fn devices(&self, token: &str) -> anyhow::Result<Value> {
        self.get_json(token, "/v1/devices").await
    }

    pub async fn register_device(&self, token: &str, body: &Value) -> anyhow::Result<DeviceRegistered> {
        let v = json_or_err(
            self.http
                .post(format!("{}/v1/devices", self.base))
                .bearer_auth(token)
                .header("Idempotency-Key", uuid::Uuid::new_v4().to_string())
                .json(body)
                .send()
                .await?,
        )
        .await?;
        Ok(serde_json::from_value(v)?)
    }

    /// `GET /v1/keys`: the root-signed KeySet (COSE bytes).
    pub async fn keyset(&self) -> anyhow::Result<Vec<u8>> {
        let r = self.http.get(format!("{}/v1/keys", self.base)).send().await?.error_for_status()?;
        Ok(r.bytes().await?.to_vec())
    }

    async fn get_json(&self, token: &str, path: &str) -> anyhow::Result<Value> {
        json_or_err(self.http.get(format!("{}{path}", self.base)).bearer_auth(token).send().await?).await
    }

    /// Server-computed earnings range (always a range; base and multiplier separate; electricity subtracted).
    /// Amounts are 2.0.0 decimal strings, checked by [`crate::money::estimate_for_app`] before the app sees them.
    pub async fn estimate(&self, token: &str, device_id: &str) -> anyhow::Result<Value> {
        crate::money::estimate_for_app(self.get_json(token, &format!("/v1/estimate?device_id={device_id}")).await?)
    }
    /// Linked wallets: display only.
    pub async fn wallets(&self, token: &str) -> anyhow::Result<Value> {
        self.get_json(token, "/v1/wallets").await
    }
    /// the server's daily snapshot, amounts as 2.0.0 decimal strings ([`crate::money::earnings_for_app`]).
    pub async fn earnings_summary(&self, token: &str) -> anyhow::Result<Value> {
        crate::money::earnings_for_app(self.get_json(token, "/v1/earnings/summary").await?)
    }
    pub async fn me(&self, token: &str) -> anyhow::Result<Value> {
        self.get_json(token, "/v1/me").await
    }
    pub async fn device(&self, token: &str, device_id: &str) -> anyhow::Result<Value> {
        self.get_json(token, &format!("/v1/devices/{device_id}")).await
    }
}
