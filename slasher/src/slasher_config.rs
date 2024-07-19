use derivative::Derivative;

#[derive(Clone, Copy, Derivative)]
#[derivative(Default)]
pub struct SlasherConfig {
    #[derivative(Default(value = "54000"))]
    pub slashing_history_limit: u64,
}
