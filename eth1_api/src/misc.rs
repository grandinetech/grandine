use std::sync::Arc;

use fork_choice_control::Controller;

use crate::eth1_execution_engine::Eth1ExecutionEngine;

pub type ApiController<P, W> = Arc<Controller<P, Arc<Eth1ExecutionEngine<P>>, W>>;
pub type RealController<P> = ApiController<P, ()>;
