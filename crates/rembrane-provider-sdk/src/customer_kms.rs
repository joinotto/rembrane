use rembrane_domain::WorkspaceId;
use zeroize::Zeroizing;

use crate::ProviderError;

pub const MAX_KMS_KEY_ID_BYTES: usize = 2_048;
pub const MAX_WRAPPED_KEY_BYTES: usize = 65_536;
pub const MAX_CUSTOMER_KMS_GENERATIONS: usize = 1_024;

/// Tenant- and generation-bound context supplied to a customer KMS.
///
/// Adapters must bind this context through the provider's encryption-context
/// or authenticated-data mechanism so wrapped keys cannot move between
/// workspaces or generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomerKmsContext {
    workspace_id: WorkspaceId,
    generation: u64,
}

impl CustomerKmsContext {
    pub fn new(workspace_id: WorkspaceId, generation: u64) -> Result<Self, ProviderError> {
        if workspace_id.as_str().trim().is_empty() || generation == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "customer KMS context requires a workspace and non-zero generation".to_owned(),
            ));
        }
        Ok(Self {
            workspace_id,
            generation,
        })
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Stable, length-delimited bytes suitable for KMS authenticated context.
    #[must_use]
    pub fn associated_data(&self) -> Vec<u8> {
        let workspace = self.workspace_id.as_str().as_bytes();
        let mut data = Vec::with_capacity(8 + workspace.len() + 8);
        data.extend_from_slice(&(workspace.len() as u64).to_be_bytes());
        data.extend_from_slice(workspace);
        data.extend_from_slice(&self.generation.to_be_bytes());
        data
    }
}

/// Opaque KMS ciphertext and the exact provider key version needed to open it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomerKmsKeyReference {
    generation: u64,
    provider_key_id: String,
    wrapped_key: Vec<u8>,
}

impl CustomerKmsKeyReference {
    pub fn new(
        generation: u64,
        provider_key_id: impl Into<String>,
        wrapped_key: Vec<u8>,
    ) -> Result<Self, ProviderError> {
        let provider_key_id = provider_key_id.into();
        if generation == 0
            || provider_key_id.trim().is_empty()
            || provider_key_id.trim() != provider_key_id
            || provider_key_id.len() > MAX_KMS_KEY_ID_BYTES
            || provider_key_id.chars().any(char::is_control)
            || wrapped_key.is_empty()
            || wrapped_key.len() > MAX_WRAPPED_KEY_BYTES
        {
            return Err(ProviderError::InvalidConfiguration(
                "customer KMS key reference is invalid".to_owned(),
            ));
        }
        Ok(Self {
            generation,
            provider_key_id,
            wrapped_key,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn provider_key_id(&self) -> &str {
        &self.provider_key_id
    }

    #[must_use]
    pub fn wrapped_key(&self) -> &[u8] {
        &self.wrapped_key
    }
}

/// Customer-side adapter implemented with AWS KMS, Azure Key Vault, Google
/// Cloud KMS, or an HSM SDK. Plaintext key bytes stay inside the sidecar.
pub trait CustomerKmsAdapter {
    fn unwrap_key(
        &self,
        context: &CustomerKmsContext,
        reference: &CustomerKmsKeyReference,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudKmsBinding {
    AwsEncryptionContext,
    AzureAdditionalAuthenticatedData,
    GoogleAdditionalAuthenticatedData,
}

/// Borrowed cloud decrypt operation. Implementations map `associated_data`
/// into the provider mechanism named by `binding`; silently discarding it
/// violates the adapter contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloudKmsDecryptRequest<'request> {
    binding: CloudKmsBinding,
    provider_key_id: &'request str,
    wrapped_key: &'request [u8],
    associated_data: &'request [u8],
}

impl CloudKmsDecryptRequest<'_> {
    #[must_use]
    pub const fn binding(&self) -> CloudKmsBinding {
        self.binding
    }

    #[must_use]
    pub const fn provider_key_id(&self) -> &str {
        self.provider_key_id
    }

    #[must_use]
    pub const fn wrapped_key(&self) -> &[u8] {
        self.wrapped_key
    }

    #[must_use]
    pub const fn associated_data(&self) -> &[u8] {
        self.associated_data
    }
}

/// Injectable customer-owned cloud SDK boundary.
pub trait CloudKmsDecryptClient {
    fn decrypt(
        &self,
        request: CloudKmsDecryptRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloudKmsGenerateRequest<'request> {
    binding: CloudKmsBinding,
    associated_data: &'request [u8],
    plaintext_key_bytes: usize,
}

impl CloudKmsGenerateRequest<'_> {
    #[must_use]
    pub const fn binding(&self) -> CloudKmsBinding {
        self.binding
    }

    #[must_use]
    pub const fn associated_data(&self) -> &[u8] {
        self.associated_data
    }

    #[must_use]
    pub const fn plaintext_key_bytes(&self) -> usize {
        self.plaintext_key_bytes
    }
}

/// Customer-cloud response containing one newly generated data key.
///
/// This type intentionally has no `Debug` or `Clone` implementation because
/// it temporarily owns plaintext key material.
pub struct CloudKmsGeneratedKey {
    provider_key_id: String,
    wrapped_key: Vec<u8>,
    plaintext_key: Zeroizing<Vec<u8>>,
}

impl CloudKmsGeneratedKey {
    pub fn new(
        provider_key_id: impl Into<String>,
        wrapped_key: Vec<u8>,
        plaintext_key: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ProviderError> {
        CustomerKmsKeyReference::new(1, provider_key_id.into(), wrapped_key).map(|validated| Self {
            provider_key_id: validated.provider_key_id,
            wrapped_key: validated.wrapped_key,
            plaintext_key,
        })
    }

    fn into_parts(self) -> (String, Vec<u8>, Zeroizing<Vec<u8>>) {
        (self.provider_key_id, self.wrapped_key, self.plaintext_key)
    }
}

pub trait CloudKmsKeyClient: CloudKmsDecryptClient {
    fn generate_data_key(
        &self,
        request: CloudKmsGenerateRequest<'_>,
    ) -> Result<CloudKmsGeneratedKey, ProviderError>;
}

/// Newly generated key material kept inside the customer-side process.
///
/// Persist `reference` durably before activating the accompanying plaintext
/// key in a record cipher.
pub struct CustomerKmsGeneratedKey {
    reference: CustomerKmsKeyReference,
    plaintext_key: Zeroizing<Vec<u8>>,
}

impl CustomerKmsGeneratedKey {
    #[must_use]
    pub const fn reference(&self) -> &CustomerKmsKeyReference {
        &self.reference
    }

    #[must_use]
    pub fn plaintext_key(&self) -> &[u8] {
        &self.plaintext_key
    }

    #[must_use]
    pub fn into_plaintext_key(self) -> Zeroizing<Vec<u8>> {
        self.plaintext_key
    }
}

pub trait CustomerKmsRotationAdapter: CustomerKmsAdapter {
    fn generate_key(
        &self,
        context: &CustomerKmsContext,
    ) -> Result<CustomerKmsGeneratedKey, ProviderError>;
}

/// Durable customer-side storage for wrapped-key rotation state.
///
/// Implementations must atomically verify `expected_active_generation`,
/// append `reference`, and make it active. Plaintext key material is never
/// passed to this boundary.
pub trait CustomerKmsKeyReferenceStore {
    fn persist_and_activate(
        &self,
        workspace_id: &WorkspaceId,
        expected_active_generation: u64,
        reference: &CustomerKmsKeyReference,
    ) -> Result<(), ProviderError>;
}

macro_rules! cloud_adapter {
    ($adapter:ident, $binding:expr) => {
        pub struct $adapter<Client> {
            client: Client,
        }

        impl<Client> $adapter<Client> {
            #[must_use]
            pub const fn new(client: Client) -> Self {
                Self { client }
            }

            #[must_use]
            pub const fn client(&self) -> &Client {
                &self.client
            }
        }

        impl<Client: CloudKmsDecryptClient> CustomerKmsAdapter for $adapter<Client> {
            fn unwrap_key(
                &self,
                context: &CustomerKmsContext,
                reference: &CustomerKmsKeyReference,
            ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
                if context.generation() != reference.generation() {
                    return Err(ProviderError::Rejected(
                        "customer KMS generation substitution".to_owned(),
                    ));
                }
                let associated_data = context.associated_data();
                self.client.decrypt(CloudKmsDecryptRequest {
                    binding: $binding,
                    provider_key_id: reference.provider_key_id(),
                    wrapped_key: reference.wrapped_key(),
                    associated_data: &associated_data,
                })
            }
        }

        impl<Client: CloudKmsKeyClient> CustomerKmsRotationAdapter for $adapter<Client> {
            fn generate_key(
                &self,
                context: &CustomerKmsContext,
            ) -> Result<CustomerKmsGeneratedKey, ProviderError> {
                let associated_data = context.associated_data();
                let generated = self.client.generate_data_key(CloudKmsGenerateRequest {
                    binding: $binding,
                    associated_data: &associated_data,
                    plaintext_key_bytes: 32,
                })?;
                let (provider_key_id, wrapped_key, plaintext_key) = generated.into_parts();
                if plaintext_key.len() != 32 {
                    return Err(ProviderError::Rejected(
                        "customer KMS returned an invalid data-key length".to_owned(),
                    ));
                }
                Ok(CustomerKmsGeneratedKey {
                    reference: CustomerKmsKeyReference::new(
                        context.generation(),
                        provider_key_id,
                        wrapped_key,
                    )?,
                    plaintext_key,
                })
            }
        }
    };
}

cloud_adapter!(AwsKmsAdapter, CloudKmsBinding::AwsEncryptionContext);
cloud_adapter!(
    AzureKeyVaultAdapter,
    CloudKmsBinding::AzureAdditionalAuthenticatedData
);
cloud_adapter!(
    GoogleCloudKmsAdapter,
    CloudKmsBinding::GoogleAdditionalAuthenticatedData
);

/// Duplicate-safe active and historical wrapped workspace keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomerKmsKeyring {
    active_generation: u64,
    references: Vec<CustomerKmsKeyReference>,
}

impl CustomerKmsKeyring {
    pub fn new(
        active_generation: u64,
        mut references: Vec<CustomerKmsKeyReference>,
    ) -> Result<Self, ProviderError> {
        references.sort_by_key(CustomerKmsKeyReference::generation);
        if active_generation == 0
            || references.is_empty()
            || references.len() > MAX_CUSTOMER_KMS_GENERATIONS
            || references
                .windows(2)
                .any(|pair| pair[0].generation() == pair[1].generation())
            || !references
                .iter()
                .any(|reference| reference.generation() == active_generation)
        {
            return Err(ProviderError::InvalidConfiguration(
                "customer KMS keyring requires one active, unique generation".to_owned(),
            ));
        }
        Ok(Self {
            active_generation,
            references,
        })
    }

    #[must_use]
    pub const fn active_generation(&self) -> u64 {
        self.active_generation
    }

    #[must_use]
    pub fn references(&self) -> &[CustomerKmsKeyReference] {
        &self.references
    }

    pub fn unwrap_active<Adapter: CustomerKmsAdapter>(
        &self,
        workspace_id: &WorkspaceId,
        adapter: &Adapter,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        self.unwrap_generation(workspace_id, self.active_generation, adapter)
    }

    pub fn unwrap_generation<Adapter: CustomerKmsAdapter>(
        &self,
        workspace_id: &WorkspaceId,
        generation: u64,
        adapter: &Adapter,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let reference = self
            .references
            .iter()
            .find(|reference| reference.generation() == generation)
            .ok_or(ProviderError::Unavailable)?;
        let context = CustomerKmsContext::new(workspace_id.clone(), generation)?;
        adapter.unwrap_key(&context, reference)
    }

    /// Generates and durably persists the strict next generation before
    /// returning plaintext key material to the caller for activation.
    pub fn generate_and_persist_next<Adapter, Store>(
        &self,
        workspace_id: &WorkspaceId,
        adapter: &Adapter,
        store: &Store,
    ) -> Result<CustomerKmsGeneratedKey, ProviderError>
    where
        Adapter: CustomerKmsRotationAdapter,
        Store: CustomerKmsKeyReferenceStore,
    {
        let next_generation = self
            .active_generation
            .checked_add(1)
            .ok_or(ProviderError::Unavailable)?;
        let context = CustomerKmsContext::new(workspace_id.clone(), next_generation)?;
        let generated = adapter.generate_key(&context)?;
        if generated.reference().generation() != next_generation {
            return Err(ProviderError::Rejected(
                "customer KMS generated an unexpected key generation".to_owned(),
            ));
        }
        store.persist_and_activate(workspace_id, self.active_generation, generated.reference())?;
        Ok(generated)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use rembrane_domain::WorkspaceId;
    use zeroize::Zeroizing;

    use super::{
        AwsKmsAdapter, AzureKeyVaultAdapter, CloudKmsBinding, CloudKmsDecryptClient,
        CloudKmsDecryptRequest, CloudKmsGenerateRequest, CloudKmsGeneratedKey, CloudKmsKeyClient,
        CustomerKmsAdapter, CustomerKmsContext, CustomerKmsKeyReference,
        CustomerKmsKeyReferenceStore, CustomerKmsKeyring, CustomerKmsRotationAdapter,
        GoogleCloudKmsAdapter,
    };
    use crate::ProviderError;

    struct RecordingAdapter {
        observed: RefCell<Vec<u8>>,
    }

    impl CustomerKmsAdapter for RecordingAdapter {
        fn unwrap_key(
            &self,
            context: &CustomerKmsContext,
            reference: &CustomerKmsKeyReference,
        ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
            *self.observed.borrow_mut() = context.associated_data();
            Ok(Zeroizing::new(reference.wrapped_key().to_vec()))
        }
    }

    #[test]
    fn active_and_historical_generations_are_context_bound() {
        let keyring = CustomerKmsKeyring::new(
            2,
            vec![
                CustomerKmsKeyReference::new(2, "kms/key/versions/2", vec![2; 32]).unwrap(),
                CustomerKmsKeyReference::new(1, "kms/key/versions/1", vec![1; 32]).unwrap(),
            ],
        )
        .unwrap();
        let adapter = RecordingAdapter {
            observed: RefCell::new(Vec::new()),
        };

        let key = keyring
            .unwrap_generation(&WorkspaceId::new("workspace-a"), 1, &adapter)
            .unwrap();

        assert_eq!(key.as_slice(), &[1; 32]);
        assert_eq!(
            adapter.observed.into_inner(),
            CustomerKmsContext::new(WorkspaceId::new("workspace-a"), 1)
                .unwrap()
                .associated_data()
        );
    }

    #[test]
    fn duplicate_missing_and_unknown_generations_fail_closed() {
        let duplicate = CustomerKmsKeyring::new(
            1,
            vec![
                CustomerKmsKeyReference::new(1, "key-a", vec![1]).unwrap(),
                CustomerKmsKeyReference::new(1, "key-b", vec![2]).unwrap(),
            ],
        );
        assert!(duplicate.is_err());

        let missing_active = CustomerKmsKeyring::new(
            2,
            vec![CustomerKmsKeyReference::new(1, "key-a", vec![1]).unwrap()],
        );
        assert!(missing_active.is_err());

        let keyring = CustomerKmsKeyring::new(
            1,
            vec![CustomerKmsKeyReference::new(1, "key-a", vec![1]).unwrap()],
        )
        .unwrap();
        let adapter = RecordingAdapter {
            observed: RefCell::new(Vec::new()),
        };
        assert_eq!(
            keyring.unwrap_generation(&WorkspaceId::new("workspace-a"), 2, &adapter),
            Err(ProviderError::Unavailable)
        );
    }

    #[test]
    fn references_reject_ambiguous_or_oversized_metadata() {
        assert!(CustomerKmsKeyReference::new(0, "key", vec![1]).is_err());
        assert!(CustomerKmsKeyReference::new(1, " key", vec![1]).is_err());
        assert!(CustomerKmsKeyReference::new(1, "key\nother", vec![1]).is_err());
        assert!(CustomerKmsKeyReference::new(1, "key", Vec::new()).is_err());
    }

    #[test]
    fn keyrings_reject_unbounded_historical_generations() {
        let references = (1..=super::MAX_CUSTOMER_KMS_GENERATIONS + 1)
            .map(|generation| {
                CustomerKmsKeyReference::new(
                    generation as u64,
                    format!("key-{generation}"),
                    vec![1],
                )
                .unwrap()
            })
            .collect();

        assert!(CustomerKmsKeyring::new(1, references).is_err());
    }

    struct RecordingCloudClient {
        binding: RefCell<Option<CloudKmsBinding>>,
        associated_data: RefCell<Vec<u8>>,
    }

    impl CloudKmsDecryptClient for RecordingCloudClient {
        fn decrypt(
            &self,
            request: CloudKmsDecryptRequest<'_>,
        ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
            *self.binding.borrow_mut() = Some(request.binding());
            *self.associated_data.borrow_mut() = request.associated_data().to_vec();
            assert_eq!(request.provider_key_id(), "provider-key");
            Ok(Zeroizing::new(request.wrapped_key().to_vec()))
        }
    }

    impl CloudKmsKeyClient for RecordingCloudClient {
        fn generate_data_key(
            &self,
            request: CloudKmsGenerateRequest<'_>,
        ) -> Result<CloudKmsGeneratedKey, ProviderError> {
            *self.binding.borrow_mut() = Some(request.binding());
            *self.associated_data.borrow_mut() = request.associated_data().to_vec();
            assert_eq!(request.plaintext_key_bytes(), 32);
            CloudKmsGeneratedKey::new("provider-key-v8", vec![8; 48], Zeroizing::new(vec![8; 32]))
        }
    }

    fn cloud_client() -> RecordingCloudClient {
        RecordingCloudClient {
            binding: RefCell::new(None),
            associated_data: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn cloud_adapters_select_provider_specific_authenticated_context() {
        let context = CustomerKmsContext::new(WorkspaceId::new("workspace-a"), 7).unwrap();
        let reference = CustomerKmsKeyReference::new(7, "provider-key", vec![9; 32]).unwrap();

        let aws = AwsKmsAdapter::new(cloud_client());
        assert_eq!(aws.unwrap_key(&context, &reference).unwrap().len(), 32);
        assert_eq!(
            *aws.client().binding.borrow(),
            Some(CloudKmsBinding::AwsEncryptionContext)
        );
        assert_eq!(
            *aws.client().associated_data.borrow(),
            context.associated_data()
        );

        let azure = AzureKeyVaultAdapter::new(cloud_client());
        azure.unwrap_key(&context, &reference).unwrap();
        assert_eq!(
            *azure.client().binding.borrow(),
            Some(CloudKmsBinding::AzureAdditionalAuthenticatedData)
        );

        let google = GoogleCloudKmsAdapter::new(cloud_client());
        google.unwrap_key(&context, &reference).unwrap();
        assert_eq!(
            *google.client().binding.borrow(),
            Some(CloudKmsBinding::GoogleAdditionalAuthenticatedData)
        );
    }

    #[test]
    fn cloud_adapters_reject_generation_substitution_before_client_access() {
        let adapter = AwsKmsAdapter::new(cloud_client());
        let context = CustomerKmsContext::new(WorkspaceId::new("workspace-a"), 2).unwrap();
        let reference = CustomerKmsKeyReference::new(1, "provider-key", vec![9; 32]).unwrap();

        assert!(adapter.unwrap_key(&context, &reference).is_err());
        assert_eq!(*adapter.client().binding.borrow(), None);
    }

    #[test]
    fn cloud_rotation_returns_persistable_reference_and_zeroizing_plaintext() {
        let adapter = GoogleCloudKmsAdapter::new(cloud_client());
        let context = CustomerKmsContext::new(WorkspaceId::new("workspace-a"), 8).unwrap();

        let generated = adapter.generate_key(&context).unwrap();

        assert_eq!(generated.reference().generation(), 8);
        assert_eq!(generated.reference().provider_key_id(), "provider-key-v8");
        assert_eq!(generated.reference().wrapped_key(), &[8; 48]);
        assert_eq!(generated.plaintext_key(), &[8; 32]);
        assert_eq!(
            *adapter.client().binding.borrow(),
            Some(CloudKmsBinding::GoogleAdditionalAuthenticatedData)
        );
        assert_eq!(
            *adapter.client().associated_data.borrow(),
            context.associated_data()
        );
    }

    struct WrongLengthCloudClient(RecordingCloudClient);

    impl CloudKmsDecryptClient for WrongLengthCloudClient {
        fn decrypt(
            &self,
            request: CloudKmsDecryptRequest<'_>,
        ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
            self.0.decrypt(request)
        }
    }

    impl CloudKmsKeyClient for WrongLengthCloudClient {
        fn generate_data_key(
            &self,
            _request: CloudKmsGenerateRequest<'_>,
        ) -> Result<CloudKmsGeneratedKey, ProviderError> {
            CloudKmsGeneratedKey::new("provider-key", vec![1; 48], Zeroizing::new(vec![1; 31]))
        }
    }

    #[test]
    fn cloud_rotation_rejects_non_256_bit_plaintext_keys() {
        let adapter = AwsKmsAdapter::new(WrongLengthCloudClient(cloud_client()));
        let context = CustomerKmsContext::new(WorkspaceId::new("workspace-a"), 2).unwrap();

        assert!(adapter.generate_key(&context).is_err());
    }

    struct RecordingReferenceStore {
        expected_active: RefCell<Option<u64>>,
        persisted_generation: RefCell<Option<u64>>,
        reject: bool,
    }

    impl CustomerKmsKeyReferenceStore for RecordingReferenceStore {
        fn persist_and_activate(
            &self,
            _workspace_id: &WorkspaceId,
            expected_active_generation: u64,
            reference: &CustomerKmsKeyReference,
        ) -> Result<(), ProviderError> {
            *self.expected_active.borrow_mut() = Some(expected_active_generation);
            *self.persisted_generation.borrow_mut() = Some(reference.generation());
            if self.reject {
                return Err(ProviderError::Unavailable);
            }
            Ok(())
        }
    }

    #[test]
    fn rotation_persists_strict_next_generation_before_returning_plaintext() {
        let adapter = GoogleCloudKmsAdapter::new(cloud_client());
        let keyring = CustomerKmsKeyring::new(
            7,
            vec![CustomerKmsKeyReference::new(7, "provider-key-v7", vec![7; 48]).unwrap()],
        )
        .unwrap();
        let store = RecordingReferenceStore {
            expected_active: RefCell::new(None),
            persisted_generation: RefCell::new(None),
            reject: false,
        };

        let generated = keyring
            .generate_and_persist_next(&WorkspaceId::new("workspace-a"), &adapter, &store)
            .unwrap();

        assert_eq!(generated.reference().generation(), 8);
        assert_eq!(*store.expected_active.borrow(), Some(7));
        assert_eq!(*store.persisted_generation.borrow(), Some(8));
    }

    #[test]
    fn rotation_does_not_release_plaintext_when_persistence_fails() {
        let adapter = GoogleCloudKmsAdapter::new(cloud_client());
        let keyring = CustomerKmsKeyring::new(
            7,
            vec![CustomerKmsKeyReference::new(7, "provider-key-v7", vec![7; 48]).unwrap()],
        )
        .unwrap();
        let store = RecordingReferenceStore {
            expected_active: RefCell::new(None),
            persisted_generation: RefCell::new(None),
            reject: true,
        };

        assert!(
            keyring
                .generate_and_persist_next(&WorkspaceId::new("workspace-a"), &adapter, &store)
                .is_err()
        );
        assert_eq!(*store.persisted_generation.borrow(), Some(8));
    }
}
