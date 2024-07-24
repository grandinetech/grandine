// The `unused_crate_dependencies` lint checks every crate in a package separately.
// See <https://github.com/rust-lang/rust/issues/57274>.
#![allow(unused_crate_dependencies)]

use core::{
    fmt::Display,
    sync::atomic::{AtomicBool, Ordering},
};

use log::{info, warn};
use parse_display::{Display, FromStr};
use variant_count::VariantCount;

// This is the only way to initialize a static array without repeating the value. See:
// - <https://github.com/rust-lang/rust/pull/79270>
// - <https://github.com/rust-lang/rust-clippy/issues/7665>
//
// The documentation of `clippy::declare_interior_mutable_const` acknowledges this:
// <https://rust-lang.github.io/rust-clippy/rust-1.75.0/#/declare_interior_mutable_const>
#[allow(clippy::declare_interior_mutable_const)]
const FALSE: AtomicBool = AtomicBool::new(false);

static FEATURES: [AtomicBool; Feature::VARIANT_COUNT] = [FALSE; Feature::VARIANT_COUNT];

#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, FromStr, VariantCount)]
pub enum Feature {
    AggregateAllAttestations,
    AlwaysPrepackAttestations,
    AlwaysPrepareExecutionPayload,
    CacheTargetStates,
    DebugAttestationPacker,
    DebugBlockProducer,
    DebugEth1,
    DebugP2p,
    IgnoreAttestationsForUnknownBlocks,
    IgnoreFutureAttestations,
    InhibitApplicationRestart,
    LogBlockProcessingTime,
    LogHttpBodies,
    LogHttpHeaders,
    LogHttpRequests,
    PatchHttpContentType,
    PrometheusMetrics,
    PublishAttestationsEarly,
    PublishSyncCommitteeMessagesEarly,
    ServeCostlyEndpoints,
    ServeLeakyEndpoints,
    SubscribeToAllAttestationSubnets,
    SubscribeToAllSyncCommitteeSubnets,
    TrackMetrics,
    TrustBackSyncBlocks,
    // By default we fully validate objects produced by the current instance of the application.
    // This costs some resources but may help in case of bugs.
    TrustOwnAttestationSignatures,
    TrustOwnAttesterSlashingSignatures,
    TrustOwnBlockSignatures,
    TrustOwnStateRoots,
    WarnOnStateCacheSlotProcessing,
}

impl Feature {
    // `Ordering::SeqCst` is slightly slower, but using other orderings could result in strange
    // behaviors. See the following for examples:
    // - <https://stackoverflow.com/questions/14861822/acquire-release-versus-sequentially-consistent-memory-order/14864466#14864466>
    // - <https://stackoverflow.com/questions/12340773/how-do-memory-order-seq-cst-and-memory-order-acq-rel-differ/12340924#12340924>
    const ORDERING: Ordering = Ordering::SeqCst;

    #[inline]
    #[must_use]
    pub fn is_enabled(self) -> bool {
        FEATURES[self as usize].load(Self::ORDERING)
    }

    #[inline]
    pub fn enable(self) {
        FEATURES[self as usize].store(true, Self::ORDERING)
    }

    pub fn log(self, message: impl Display) {
        // This seems like something that would be better done using structured logging.
        // Maybe `log::kv` will be stable someday. Or we could implement it ourselves.
        info!("[{self}] {message}");
    }

    pub fn warn(self, message: impl Display) {
        warn!("[{self}] {message}");
    }
}

#[macro_export]
macro_rules! log {
    ($feature: ident, $($message: tt)+) => {{
        let feature = $crate::Feature::$feature;
        if feature.is_enabled() {
            feature.log(format_args!($($message)+))
        }
    }};
}
