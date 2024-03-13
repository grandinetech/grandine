use helper_functions::{error::SignatureKind, signing::SignForAllForks};
use types::{phase0::primitives::DomainType, preset::Preset};

use crate::{
    bellatrix::containers::BuilderBid as BellatrixBuilderBid,
    capella::containers::BuilderBid as CapellaBuilderBid, consts::DOMAIN_APPLICATION_BUILDER,
    deneb::containers::BuilderBid as DenebBuilderBid,
    unphased::containers::ValidatorRegistrationV1,
};

/// <https://github.com/ethereum/builder-specs/blob/d246d57ba2a0c2378c1de4a2bdaff7cd438e99ee/specs/builder.md#signing>
impl<P: Preset> SignForAllForks for BellatrixBuilderBid<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_APPLICATION_BUILDER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Builder;
}

/// <https://github.com/ethereum/builder-specs/blob/d246d57ba2a0c2378c1de4a2bdaff7cd438e99ee/specs/builder.md#signing>
impl<P: Preset> SignForAllForks for CapellaBuilderBid<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_APPLICATION_BUILDER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Builder;
}

/// <https://github.com/ethereum/builder-specs/blob/d246d57ba2a0c2378c1de4a2bdaff7cd438e99ee/specs/builder.md#signing>
impl<P: Preset> SignForAllForks for DenebBuilderBid<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_APPLICATION_BUILDER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Builder;
}

/// <https://github.com/ethereum/builder-specs/blob/d246d57ba2a0c2378c1de4a2bdaff7cd438e99ee/specs/builder.md#signing>
impl SignForAllForks for ValidatorRegistrationV1 {
    const DOMAIN_TYPE: DomainType = DOMAIN_APPLICATION_BUILDER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Builder;
}
