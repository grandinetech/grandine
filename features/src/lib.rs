#![allow(
    unused_crate_dependencies,
    reason = "The `unused_crate_dependencies` lint checks every crate in a package separately. \
              See <https://github.com/rust-lang/rust/issues/57274>."
)]

use core::{
    fmt::Display,
    sync::atomic::{AtomicBool, Ordering},
};

use log::{info, warn};
use parse_display::{Display, FromStr};
use variant_count::VariantCount;

static FEATURES: [AtomicBool; Feature::VARIANT_COUNT] =
    [const { AtomicBool::new(false) }; Feature::VARIANT_COUNT];

#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, FromStr, VariantCount)]
pub enum Feature {
    AggregateAllAttestations,
    AlwaysPrepackAttestations,
    AlwaysPrepareExecutionPayload,
    CacheTargetStates,
    DebugAttestationPacker,
    DebugBlockProducer,
    DebugEth1,
    DebugP2pMessages,
    DumpAggregateAttestations,
    DumpBeaconBlocks,
    DumpBeaconStates,
    DumpBlobSidecars,
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
    SubscribeToAllDataColumnSubnets,
    SubscribeToAllSyncCommitteeSubnets,
    TrackMetrics,
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
