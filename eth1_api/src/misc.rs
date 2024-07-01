use std::sync::Arc;

use fork_choice_control::{AttestationVerifierMessage, Controller};
use futures::channel::mpsc::UnboundedSender;

use crate::eth1_execution_engine::Eth1ExecutionEngine;

pub type AttestationVerifierSender<P, W> = UnboundedSender<AttestationVerifierMessage<P, W>>;

pub type ApiController<P, W> =
    Arc<Controller<P, Arc<Eth1ExecutionEngine<P>>, AttestationVerifierSender<P, W>, W>>;

pub type RealController<P> = ApiController<P, ()>;
