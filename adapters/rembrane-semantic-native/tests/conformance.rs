use rembrane_provider_sdk::verify_semantic_provider;
use rembrane_semantic_native::NativeSemanticProvider;

#[test]
fn native_provider_passes_shared_conformance_suite() {
    verify_semantic_provider(&mut NativeSemanticProvider::new(), "native")
        .expect("native provider should satisfy the shared provider contract");
}
