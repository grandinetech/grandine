use educe::Educe;

#[derive(Clone, Copy, Educe)]
#[educe(Default)]
pub struct SlasherConfig {
    #[educe(Default = 54000)]
    pub slashing_history_limit: u64,
}
