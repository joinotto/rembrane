use std::error::Error;
use std::fmt::{Display, Formatter};

use rembrane_provider_sdk::{
    SEMANTIC_PROVIDER_CONFORMANCE_CASES, SEMANTIC_PROVIDER_CONFORMANCE_PROFILE_SHA256,
    SEMANTIC_PROVIDER_CONFORMANCE_SUITE_ID, SEMANTIC_PROVIDER_CONFORMANCE_SUITE_VERSION,
};
use serde::Serialize;

use crate::{RegistryTrust, VerifiedProviderRegistry};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderSelectionPolicy<'value> {
    pub provider_id: &'value str,
    pub adapter_version: &'value str,
    pub allow_experimental: bool,
    pub allow_provider_plaintext: bool,
    pub now_epoch_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSelectionReceipt {
    pub schema_version: u8,
    pub registry_generated_at: String,
    pub registry_sha256: String,
    pub registry_trust: ProviderSelectionTrust,
    pub provider: String,
    pub adapter_version: String,
    pub status: String,
    pub eligibility: ProviderEligibility,
    pub protocol_version: String,
    pub deployment_modes: Vec<String>,
    pub plaintext_processing: bool,
    pub approvals: ProviderSelectionApprovals,
    pub evidence: ProviderSelectionEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum ProviderSelectionTrust {
    Embedded,
    Ed25519 {
        #[serde(rename = "publicKeySha256")]
        public_key_sha256: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderEligibility {
    Compatible,
    ExperimentalOptIn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSelectionApprovals {
    pub experimental: bool,
    pub provider_plaintext: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSelectionEvidence {
    pub suite_id: String,
    pub suite_version: String,
    pub profile_sha256: String,
    pub tested_at: String,
    pub source_revision: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderRegistrySelectionError(&'static str);

impl Display for ProviderRegistrySelectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for ProviderRegistrySelectionError {}

pub(crate) fn select(
    verified: &VerifiedProviderRegistry,
    policy: &ProviderSelectionPolicy<'_>,
) -> Result<ProviderSelectionReceipt, ProviderRegistrySelectionError> {
    let registry_text = std::str::from_utf8(verified.bytes())
        .map_err(|_| error("provider registry is not UTF-8"))?;
    let registry: serde_json::Value = serde_json::from_str(registry_text)
        .map_err(|_| error("provider registry is not valid JSON"))?;
    let generated_at = string(&registry, "generatedAt")?;
    let generated_epoch = timestamp(generated_at)
        .ok_or_else(|| error("provider registry generation timestamp is invalid"))?;
    if generated_epoch > policy.now_epoch_seconds {
        return Err(error(
            "provider registry generation timestamp is in the future",
        ));
    }
    let providers = registry
        .get("providers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| error("provider registry has no provider array"))?;
    let matches = providers
        .iter()
        .filter(|provider| {
            provider.get("id").and_then(serde_json::Value::as_str) == Some(policy.provider_id)
        })
        .collect::<Vec<_>>();
    let [provider] = matches.as_slice() else {
        return Err(error(
            "provider registry does not contain exactly one matching provider",
        ));
    };
    if string(provider, "adapterVersion")? != policy.adapter_version {
        return Err(error(
            "provider adapter version does not match registry evidence",
        ));
    }
    let evidence = validate_evidence(provider, policy.adapter_version, generated_epoch)?;
    let status = string(provider, "status")?;
    let eligibility = match status {
        "compatible" => ProviderEligibility::Compatible,
        "experimental" if policy.allow_experimental => ProviderEligibility::ExperimentalOptIn,
        "experimental" => {
            return Err(error("experimental provider requires --allow-experimental"));
        }
        "deprecated" => {
            return Err(error(
                "deprecated provider is not eligible for new selection",
            ));
        }
        "revoked" => return Err(error("revoked provider is not eligible for selection")),
        _ => return Err(error("provider registry status is invalid")),
    };
    let plaintext_processing = provider
        .get("plaintextProcessing")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| error("provider plaintext policy is invalid"))?;
    if plaintext_processing && !policy.allow_provider_plaintext {
        return Err(error(
            "plaintext provider requires --allow-provider-plaintext",
        ));
    }
    let deployment_modes = provider
        .get("deploymentModes")
        .and_then(serde_json::Value::as_array)
        .filter(|modes| !modes.is_empty())
        .ok_or_else(|| error("provider deployment evidence is invalid"))?
        .iter()
        .map(|mode| {
            mode.as_str()
                .filter(|value| {
                    matches!(
                        *value,
                        "embedded" | "local-service" | "self-hosted" | "managed"
                    )
                })
                .map(str::to_owned)
                .ok_or_else(|| error("provider deployment evidence is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let trust = match verified.trust() {
        RegistryTrust::Embedded => ProviderSelectionTrust::Embedded,
        RegistryTrust::Ed25519 { public_key_sha256 } => ProviderSelectionTrust::Ed25519 {
            public_key_sha256: public_key_sha256.clone(),
        },
    };
    Ok(ProviderSelectionReceipt {
        schema_version: 1,
        registry_generated_at: generated_at.to_owned(),
        registry_sha256: verified.sha256().to_owned(),
        registry_trust: trust,
        provider: policy.provider_id.to_owned(),
        adapter_version: policy.adapter_version.to_owned(),
        status: status.to_owned(),
        eligibility,
        protocol_version: evidence.0,
        deployment_modes,
        plaintext_processing,
        approvals: ProviderSelectionApprovals {
            experimental: status == "experimental" && policy.allow_experimental,
            provider_plaintext: plaintext_processing && policy.allow_provider_plaintext,
        },
        evidence: evidence.1,
    })
}

fn validate_evidence(
    provider: &serde_json::Value,
    adapter_version: &str,
    generated_epoch: i64,
) -> Result<(String, ProviderSelectionEvidence), ProviderRegistrySelectionError> {
    let source_revision = provider
        .pointer("/source/revision")
        .and_then(serde_json::Value::as_str)
        .filter(|revision| {
            (7..=64).contains(&revision.len())
                && revision
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| error("provider source revision is invalid"))?;
    let protocols = provider
        .get("protocolVersions")
        .and_then(serde_json::Value::as_array)
        .filter(|protocols| !protocols.is_empty())
        .ok_or_else(|| error("provider protocol evidence is invalid"))?;
    let conformance = provider
        .get("conformance")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| error("provider conformance evidence is missing"))?;
    let protocol = conformance_string(conformance, "protocolVersion")?;
    if !protocols
        .iter()
        .any(|candidate| candidate.as_str() == Some(protocol))
    {
        return Err(error("provider conformance evidence is not eligible"));
    }
    let tested_at = conformance_string(conformance, "testedAt")?;
    let tested_epoch =
        timestamp(tested_at).ok_or_else(|| error("provider conformance timestamp is invalid"))?;
    if tested_epoch > generated_epoch {
        return Err(error(
            "provider conformance postdates its registry snapshot",
        ));
    }
    if conformance_string(conformance, "result")? != "pass"
        || conformance_string(conformance, "suiteId")? != SEMANTIC_PROVIDER_CONFORMANCE_SUITE_ID
        || conformance_string(conformance, "suiteVersion")?
            != SEMANTIC_PROVIDER_CONFORMANCE_SUITE_VERSION
        || conformance_string(conformance, "profileSha256")?
            != SEMANTIC_PROVIDER_CONFORMANCE_PROFILE_SHA256
        || conformance_string(conformance, "providerVersion")? != adapter_version
    {
        return Err(error("provider conformance evidence is not eligible"));
    }
    let cases = conformance
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| error("provider conformance cases are invalid"))?;
    if cases.len() != SEMANTIC_PROVIDER_CONFORMANCE_CASES.len()
        || cases
            .iter()
            .zip(SEMANTIC_PROVIDER_CONFORMANCE_CASES)
            .any(|(case, expected)| {
                case.get("id").and_then(serde_json::Value::as_str) != Some(expected)
                    || case.get("result").and_then(serde_json::Value::as_str) != Some("pass")
            })
    {
        return Err(error("provider conformance cases are not eligible"));
    }
    Ok((
        protocol.to_owned(),
        ProviderSelectionEvidence {
            suite_id: SEMANTIC_PROVIDER_CONFORMANCE_SUITE_ID.to_owned(),
            suite_version: SEMANTIC_PROVIDER_CONFORMANCE_SUITE_VERSION.to_owned(),
            profile_sha256: SEMANTIC_PROVIDER_CONFORMANCE_PROFILE_SHA256.to_owned(),
            tested_at: tested_at.to_owned(),
            source_revision: source_revision.to_owned(),
        },
    ))
}

fn string<'value>(
    value: &'value serde_json::Value,
    field: &str,
) -> Result<&'value str, ProviderRegistrySelectionError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| error("provider registry field is invalid"))
}

fn conformance_string<'value>(
    value: &'value serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'value str, ProviderRegistrySelectionError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| error("provider conformance evidence is invalid"))
}

fn timestamp(value: &str) -> Option<i64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value).ok()?;
    (parsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true) == value).then(|| parsed.timestamp())
}

const fn error(message: &'static str) -> ProviderRegistrySelectionError {
    ProviderRegistrySelectionError(message)
}

#[cfg(test)]
mod tests {
    use super::{ProviderEligibility, ProviderSelectionPolicy};
    use crate::VerifiedProviderRegistry;

    const REGISTRY: &[u8] = include_bytes!("../../../spec/provider-registry.json");
    const NOW: i64 = 1_793_000_000;

    fn policy(
        version: &str,
        allow_experimental: bool,
        allow_plaintext: bool,
    ) -> ProviderSelectionPolicy<'_> {
        ProviderSelectionPolicy {
            provider_id: "rembrane.native",
            adapter_version: version,
            allow_experimental,
            allow_provider_plaintext: allow_plaintext,
            now_epoch_seconds: NOW,
        }
    }

    #[test]
    fn selects_exact_approved_build_and_emits_typed_receipt() {
        let registry = VerifiedProviderRegistry::embedded(REGISTRY);
        let receipt = registry
            .select(&policy("0.1.0-alpha.1", true, true))
            .expect("approved provider");

        assert_eq!(receipt.provider, "rembrane.native");
        assert_eq!(receipt.eligibility, ProviderEligibility::ExperimentalOptIn);
        assert!(receipt.approvals.experimental);
        assert!(receipt.approvals.provider_plaintext);
        let json = serde_json::to_value(receipt).expect("serialize receipt");
        assert_eq!(json["schemaVersion"], 1);
        assert_eq!(json["registryTrust"]["mode"], "embedded");
        assert_eq!(json["protocolVersion"], "0.1");
    }

    #[test]
    fn rejects_missing_approvals_and_substituted_build() {
        let registry = VerifiedProviderRegistry::embedded(REGISTRY);
        assert!(
            registry
                .select(&policy("0.1.0-alpha.1", false, true))
                .expect_err("experimental approval")
                .to_string()
                .contains("--allow-experimental")
        );
        assert!(
            registry
                .select(&policy("0.1.0-alpha.1", true, false))
                .expect_err("plaintext approval")
                .to_string()
                .contains("--allow-provider-plaintext")
        );
        assert!(
            registry
                .select(&policy("substituted", true, true))
                .expect_err("build pin")
                .to_string()
                .contains("version")
        );
    }

    #[test]
    fn rejects_rebound_conformance_evidence() {
        let mut value: serde_json::Value =
            serde_json::from_slice(REGISTRY).expect("registry fixture");
        value["providers"][0]["conformance"]["profileSha256"] =
            serde_json::Value::String("a".repeat(64));
        let registry = VerifiedProviderRegistry::embedded(
            serde_json::to_vec(&value).expect("modified registry"),
        );

        assert!(
            registry
                .select(&policy("0.1.0-alpha.1", true, true))
                .expect_err("profile substitution")
                .to_string()
                .contains("conformance")
        );
    }
}
