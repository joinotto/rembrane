use rembrane_domain::WorkspaceId;
use zeroize::Zeroizing;

use crate::ProviderError;

pub const MAX_KMS_KEY_ID_BYTES: usize = 2_048;
pub const MAX_WRAPPED_KEY_BYTES: usize = 65_536;

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
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use rembrane_domain::WorkspaceId;
    use zeroize::Zeroizing;

    use super::{
        AwsKmsAdapter, AzureKeyVaultAdapter, CloudKmsBinding, CloudKmsDecryptClient,
        CloudKmsDecryptRequest, CustomerKmsAdapter, CustomerKmsContext, CustomerKmsKeyReference,
        CustomerKmsKeyring, GoogleCloudKmsAdapter,
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
}
