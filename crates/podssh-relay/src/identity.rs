//! The identity of each end: `pod-identity` of PodUtils/podcrates. The
//! functions that read the places of the cache take podssh's places here
//! (`crate::cache::pod_places`), so that each caller keeps its call.

pub use pod_identity::*;

pub mod file {
    pub use pod_identity::file::*;

    use pod_core::entropy::Entropy;
    use pod_identity::Identity;

    /// The key kept at `place` in podssh's places, made when there is none.
    pub fn load(place: &Place, entropy: &mut dyn Entropy) -> Result<Key, String> {
        pod_identity::file::load(&crate::cache::pod_places(), place, entropy)
    }

    /// The key kept at `place` in podssh's places, read and never made.
    pub fn existing(place: &Place) -> Result<Option<Identity>, String> {
        pod_identity::file::existing(&crate::cache::pod_places(), place)
    }
}

pub mod pins {
    pub use pod_identity::pins::*;

    use pod_identity::PublicKey;

    /// The key of the node of `label` against podssh's pins.
    pub fn check(label: &str, key: &PublicKey) -> Result<Seen, PinError> {
        pod_identity::pins::check(&crate::cache::pod_places(), label, key)
    }
}
