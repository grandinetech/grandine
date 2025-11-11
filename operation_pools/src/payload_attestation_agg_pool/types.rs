use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use bls::AggregateSignature;
use ssz::BitVector;
use tokio::sync::RwLock;
use types::{
    gloas::containers::{PayloadAttestationData, PayloadAttestationMessage},
    preset::Preset,
};

pub type AggregateMap<P> = HashMap<PayloadAttestationData, Arc<RwLock<Aggregate<P>>>>;
pub type PayloadAttestationMap =
    HashMap<PayloadAttestationData, Arc<RwLock<PayloadAttestationSet>>>;
pub type PayloadAttestationSet = HashSet<PayloadAttestationMessage>;

#[derive(Clone, Copy, Default)]
pub struct Aggregate<P: Preset> {
    pub aggregation_bits: BitVector<P::PtcSize>,
    pub signature: AggregateSignature,
}
