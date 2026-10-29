/// Variants are ordered worst first. Nodes are ranked against each other by this order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Health {
    Incompatible,
    Unreachable,
    Unusable,
    /// Synced, with a head not yet verified by an execution engine.
    Optimistic,
    Unknown,
    Ready,
}

impl Health {
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Whether the node follows the chain, verified or not.
    #[must_use]
    pub const fn is_synced(self) -> bool {
        matches!(self, Self::Optimistic | Self::Ready)
    }

    /// Whether the node may follow the chain, as no poll has shown otherwise.
    #[must_use]
    pub const fn may_be_synced(self) -> bool {
        matches!(self, Self::Optimistic | Self::Unknown | Self::Ready)
    }

    #[must_use]
    pub const fn can_serve(self) -> bool {
        // A failed poll does not mean the next request fails, so only a node on the wrong
        // network is never asked.
        !matches!(self, Self::Incompatible)
    }

    pub(crate) const fn from_syncing_status(
        el_offline: bool,
        is_syncing: bool,
        is_optimistic: bool,
    ) -> Self {
        if el_offline || is_syncing {
            return Self::Unusable;
        }

        // An optimistic head has not been verified by an execution engine.
        if is_optimistic {
            return Self::Optimistic;
        }

        Self::Ready
    }

    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    pub(crate) const fn from_u8(byte: u8) -> Self {
        match byte {
            0 => Self::Incompatible,
            1 => Self::Unreachable,
            2 => Self::Unusable,
            3 => Self::Optimistic,
            5 => Self::Ready,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_ready_node_reports_ready() {
        assert!(Health::Ready.is_ready());
        assert!(!Health::Unknown.is_ready());
        assert!(!Health::Optimistic.is_ready());
        assert!(!Health::Unusable.is_ready());
        assert!(!Health::Unreachable.is_ready());
        assert!(!Health::Incompatible.is_ready());
    }

    #[test]
    fn a_ready_or_optimistic_node_is_synced() {
        assert!(Health::Ready.is_synced());
        assert!(Health::Optimistic.is_synced());
        assert!(!Health::Unknown.is_synced());
        assert!(!Health::Unusable.is_synced());
        assert!(!Health::Unreachable.is_synced());
        assert!(!Health::Incompatible.is_synced());
    }

    #[test]
    fn a_node_may_be_synced_until_a_poll_shows_otherwise() {
        assert!(Health::Ready.may_be_synced());
        assert!(Health::Unknown.may_be_synced());
        assert!(Health::Optimistic.may_be_synced());
        assert!(!Health::Unusable.may_be_synced());
        assert!(!Health::Unreachable.may_be_synced());
        assert!(!Health::Incompatible.may_be_synced());
    }

    #[test]
    fn any_node_may_serve_but_one_on_the_wrong_network() {
        assert!(Health::Ready.can_serve());
        assert!(Health::Unknown.can_serve());
        assert!(Health::Optimistic.can_serve());
        assert!(Health::Unusable.can_serve());
        assert!(Health::Unreachable.can_serve());
        assert!(!Health::Incompatible.can_serve());
    }

    #[test]
    fn health_is_ordered_worst_first() {
        assert!(Health::Incompatible < Health::Unreachable);
        assert!(Health::Unreachable < Health::Unusable);
        assert!(Health::Unusable < Health::Optimistic);
        assert!(Health::Optimistic < Health::Unknown);
        assert!(Health::Unknown < Health::Ready);
    }

    #[test]
    fn a_syncing_node_or_one_without_an_execution_engine_is_unusable() {
        assert_eq!(
            Health::from_syncing_status(true, false, false),
            Health::Unusable,
        );

        assert_eq!(
            Health::from_syncing_status(false, true, false),
            Health::Unusable,
        );

        assert_eq!(
            Health::from_syncing_status(false, true, true),
            Health::Unusable,
        );

        assert_eq!(
            Health::from_syncing_status(false, false, true),
            Health::Optimistic,
        );

        assert_eq!(
            Health::from_syncing_status(false, false, false),
            Health::Ready,
        );
    }

    #[test]
    fn health_survives_a_round_trip_through_a_byte() {
        for health in [
            Health::Incompatible,
            Health::Unreachable,
            Health::Unusable,
            Health::Optimistic,
            Health::Unknown,
            Health::Ready,
        ] {
            assert_eq!(Health::from_u8(health.as_u8()), health);
        }
    }
}
