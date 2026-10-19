// Local regression checks. Upstream Python tests and vectors are unchanged.
// Specification baseline: consensus-specs 12c8b24bc09b12f62688d439ba20ef00b1fdfe1f.
use helper_functions::{
    signing::{RandaoEpoch, SignForSingleFork as _},
    verifier::{MultiVerifier, VerifierOption},
};
use ssz::Hc;
use typenum::Unsigned as _;
use types::preset::Preset;

#[test]
fn review_legacy_bls_reveal_still_verifies_and_uses_xor() -> Result<()> {
    let config = Config::minimal();
    let key = secret_key();
    let mut state = state_with_validator(key.to_public_key().into())?;
    let signature = RandaoEpoch::from(0).sign(&config, &state, &key).into();
    let body = BeaconBlockBody::<Minimal> {
        randao_reveal: signature,
        ..BeaconBlockBody::default()
    };
    process_randao(
        &config,
        &PubkeyCache::default(),
        &mut state,
        &body,
        SingleVerifier,
    )?;
    assert_eq!(
        *state.randao_mixes.mod_index(0),
        PREVIOUS_MIX ^ hashing::hash_768(signature)
    );
    assert!(state.randao_commitments.get(0)?.is_zero());
    Ok(())
}

#[test]
fn review_legacy_bls_rejects_signature_for_wrong_epoch() -> Result<()> {
    let config = Config::minimal();
    let key = secret_key();
    let mut state = state_with_validator(key.to_public_key().into())?;
    let body = BeaconBlockBody::<Minimal> {
        randao_reveal: RandaoEpoch::from(1).sign(&config, &state, &key).into(),
        ..BeaconBlockBody::default()
    };
    assert!(
        process_randao(
            &config,
            &PubkeyCache::default(),
            &mut state,
            &body,
            SingleVerifier
        )
        .is_err()
    );
    assert_eq!(*state.randao_mixes.mod_index(0), PREVIOUS_MIX);
    Ok(())
}

#[test]
fn review_direct_registration_rejects_tampered_signature() -> Result<()> {
    let config = Config::minimal();
    let key = secret_key();
    let mut state = state_with_validator(key.to_public_key().into())?;
    let mut message = RandaoCommitmentRegistration {
        validator_index: 0,
        commitment: H256::repeat_byte(3),
    };
    let signature = message.sign(&config, &state, &key).into();
    message.commitment = H256::repeat_byte(4);
    assert!(
        process_randao_commitment_registration(
            &config,
            &PubkeyCache::default(),
            &mut state,
            SignedRandaoCommitmentRegistration { message, signature },
            SingleVerifier,
        )
        .is_err()
    );
    assert_eq!(state.pending_randao_commitments.len_usize(), 0);
    Ok(())
}

#[test]
fn review_activation_boundary_and_replay_after_activation() -> Result<()> {
    let config = Config::minimal();
    let key = secret_key();
    let mut state = state_with_validator(key.to_public_key().into())?;
    let message = RandaoCommitmentRegistration {
        validator_index: 0,
        commitment: hashing::blake3_hash_chain_link(CHAIN_SECRET),
    };
    let registration = SignedRandaoCommitmentRegistration {
        signature: message.sign(&config, &state, &key).into(),
        message,
    };
    process_randao_commitment_registration(
        &config,
        &PubkeyCache::default(),
        &mut state,
        registration,
        SingleVerifier,
    )?;
    process_pending_randao_commitments(&mut state)?;
    assert!(state.randao_commitments.get(0)?.is_zero());
    assert_eq!(state.pending_randao_commitments.len_usize(), 1);

    state.slot = (COMMITMENT_REGISTRATION_DELAY - 1) * <Minimal as Preset>::SlotsPerEpoch::U64;
    process_pending_randao_commitments(&mut state)?;
    assert_eq!(*state.randao_commitments.get(0)?, message.commitment);
    assert_eq!(state.pending_randao_commitments.len_usize(), 0);
    assert!(
        process_randao_commitment_registration(
            &config,
            &PubkeyCache::default(),
            &mut state,
            registration,
            SingleVerifier,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn review_same_validator_consumes_two_links_in_one_epoch() -> Result<()> {
    let config = Config::minimal();
    let key = secret_key();
    let mut state = state_with_validator(key.to_public_key().into())?;
    let first = hashing::blake3_hash_chain_link(CHAIN_SECRET);
    *state.randao_commitments.get_mut(0)? = hashing::blake3_hash_chain_link(first);
    for reveal in [first, CHAIN_SECRET] {
        process_randao(
            &config,
            &PubkeyCache::default(),
            &mut state,
            &body_with_hash_chain_reveal(reveal),
            SingleVerifier,
        )?;
    }
    assert_eq!(*state.randao_commitments.get(0)?, CHAIN_SECRET);
    assert_eq!(
        *state.randao_mixes.mod_index(0),
        hashing::blake3_256_256(hashing::blake3_256_256(PREVIOUS_MIX, first), CHAIN_SECRET),
    );
    Ok(())
}

#[test]
fn review_registration_domain_matches_vector_specification() {
    assert_eq!(
        types::gloas::consts::DOMAIN_RANDAO_COMMITMENT_REGISTRATION.as_bytes(),
        &[0x11, 0, 0, 0],
        "consensus-specs 12c8b24b uses DOMAIN_RANDAO_COMMITMENT_REGISTRATION = 0x11000000",
    );
}

#[test]
fn review_block_signature_verifier_rejects_forged_registration() -> Result<()> {
    use types::gloas::containers::{BeaconBlock, SignedBeaconBlock};

    let config = Config::minimal();
    let key = secret_key();
    let state = state_with_validator(key.to_public_key().into())?;
    // Verify the real legacy RANDAO signature; isolate only the block-root and sync signatures.
    let verifier = || {
        MultiVerifier::new([
            VerifierOption::SkipBlockRootSignature,
            VerifierOption::SkipBlockSyncAggregateSignature,
        ])
    };
    let valid_empty_block = SignedBeaconBlock::<Minimal> {
        message: Hc::new(BeaconBlock {
            body: BeaconBlockBody {
                randao_reveal: RandaoEpoch::from(0).sign(&config, &state, &key).into(),
                ..BeaconBlockBody::default()
            },
            ..BeaconBlock::default()
        }),
        signature: SignatureBytes::empty(),
    };
    crate::gloas::verify_signatures(
        &config,
        &PubkeyCache::default(),
        &state,
        &valid_empty_block,
        verifier(),
    )?;

    let mut message = RandaoCommitmentRegistration {
        validator_index: 0,
        commitment: H256::repeat_byte(3),
    };
    let signature = message.sign(&config, &state, &key).into();
    message.commitment = H256::repeat_byte(4);
    let mut body = BeaconBlockBody::<Minimal> {
        randao_reveal: RandaoEpoch::from(0).sign(&config, &state, &key).into(),
        ..BeaconBlockBody::default()
    };
    body.randao_commitment_registrations =
        vec![SignedRandaoCommitmentRegistration { message, signature }].try_into()?;
    let block = SignedBeaconBlock {
        message: Hc::new(BeaconBlock {
            body,
            ..BeaconBlock::default()
        }),
        signature: SignatureBytes::empty(),
    };
    assert!(
        crate::gloas::verify_signatures(
            &config,
            &PubkeyCache::default(),
            &state,
            &block,
            verifier(),
        )
        .is_err(),
        "the block signature verification path accepted a forged registration",
    );
    Ok(())
}

#[test]
fn review_registration_block_limit_rejects_129_before_queuing() -> Result<()> {
    let config = Config::minimal();
    let key = secret_key();
    let mut state = state_with_validator(key.to_public_key().into())?;
    let registration = SignedRandaoCommitmentRegistration {
        message: RandaoCommitmentRegistration {
            validator_index: 0,
            commitment: H256::repeat_byte(3),
        },
        signature: SignatureBytes::empty(),
    };
    let body = BeaconBlockBody::<Minimal> {
        randao_commitment_registrations: vec![registration; 129].try_into()?,
        ..BeaconBlockBody::default()
    };
    let result = process_randao_commitment_registrations(
        &config,
        &PubkeyCache::default(),
        &mut state,
        &body,
        NullVerifier,
    );
    assert!(matches!(
        result
            .expect_err("129 registrations must be invalid")
            .downcast_ref::<crate::unphased::Error<Minimal>>(),
        Some(crate::unphased::Error::TooManyOperations {
            maximum: 128,
            in_block: 129,
            ..
        }),
    ));
    assert_eq!(state.pending_randao_commitments.len_usize(), 0);
    Ok(())
}

#[test]
fn review_block_verifier_accepts_a_valid_registration() -> Result<()> {
    use types::gloas::containers::{BeaconBlock, SignedBeaconBlock};
    let config = Config::minimal();
    let key = secret_key();
    let state = state_with_validator(key.to_public_key().into())?;
    let message = RandaoCommitmentRegistration {
        validator_index: 0,
        commitment: H256::repeat_byte(3),
    };
    let registration = SignedRandaoCommitmentRegistration {
        signature: message.sign(&config, &state, &key).into(),
        message,
    };
    let block = SignedBeaconBlock {
        message: Hc::new(BeaconBlock {
            body: BeaconBlockBody::<Minimal> {
                randao_reveal: RandaoEpoch::from(0).sign(&config, &state, &key).into(),
                randao_commitment_registrations: vec![registration].try_into()?,
                ..BeaconBlockBody::default()
            },
            ..BeaconBlock::default()
        }),
        signature: SignatureBytes::empty(),
    };
    crate::gloas::verify_signatures(
        &config,
        &PubkeyCache::default(),
        &state,
        &block,
        MultiVerifier::new([
            VerifierOption::SkipBlockRootSignature,
            VerifierOption::SkipBlockSyncAggregateSignature,
        ]),
    )
}
