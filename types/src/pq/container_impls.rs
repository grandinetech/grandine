use crate::{
    combined::UnblindError,
    nonstandard::ExecutionPayloadBody,
    pq::containers::{
        BlindedExecutionPayloadEnvelope, ExecutionPayloadEnvelope,
        SignedBlindedExecutionPayloadEnvelope, SignedExecutionPayloadEnvelope,
    },
    preset::Preset,
};

impl<P: Preset> SignedBlindedExecutionPayloadEnvelope<P> {
    pub fn unblind(
        self,
        payload_body: ExecutionPayloadBody<P>,
    ) -> Result<SignedExecutionPayloadEnvelope<P>, UnblindError> {
        let Self { message, signature } = self;

        Ok(SignedExecutionPayloadEnvelope {
            signature,
            message: ExecutionPayloadEnvelope {
                payload: message.payload_header.unblind(payload_body)?,
                execution_requests: message.execution_requests,
                builder_index: message.builder_index,
                beacon_block_root: message.beacon_block_root,
                parent_beacon_block_root: message.parent_beacon_block_root,
            },
        })
    }
}

impl<P: Preset> From<SignedExecutionPayloadEnvelope<P>>
    for SignedBlindedExecutionPayloadEnvelope<P>
{
    fn from(value: SignedExecutionPayloadEnvelope<P>) -> Self {
        Self {
            signature: value.signature,
            message: value.message.into(),
        }
    }
}

impl<P: Preset> From<ExecutionPayloadEnvelope<P>> for BlindedExecutionPayloadEnvelope<P> {
    fn from(value: ExecutionPayloadEnvelope<P>) -> Self {
        Self {
            payload_header: (&value.payload).into(),
            execution_requests: value.execution_requests,
            builder_index: value.builder_index,
            beacon_block_root: value.beacon_block_root,
            parent_beacon_block_root: value.parent_beacon_block_root,
        }
    }
}
