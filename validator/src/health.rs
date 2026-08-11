/// Variants are ordered worst first. Nodes are ranked against each other by this order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Health {
    Incompatible,
    Unreachable,
    Unusable,
    Unknown,
    Ready,
}

impl Health {
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    // A degraded node is still worth asking, unlike one on the wrong network or an unreachable one.
    #[must_use]
    pub const fn can_serve(self) -> bool {
        matches!(self, Self::Unusable | Self::Unknown | Self::Ready)
    }

    pub(crate) const fn from_syncing_status(
        el_offline: bool,
        is_syncing: bool,
        is_optimistic: bool,
    ) -> Self {
        // An optimistic head has not been verified by an execution engine.
        if el_offline || is_syncing || is_optimistic {
            return Self::Unusable;
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
            4 => Self::Ready,
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
        assert!(!Health::Unusable.is_ready());
        assert!(!Health::Unreachable.is_ready());
        assert!(!Health::Incompatible.is_ready());
    }

    #[test]
    fn a_degraded_node_may_serve_but_a_wrong_or_dead_one_may_not() {
        assert!(Health::Ready.can_serve());
        assert!(Health::Unknown.can_serve());
        assert!(Health::Unusable.can_serve());
        assert!(!Health::Unreachable.can_serve());
        assert!(!Health::Incompatible.can_serve());
    }

    #[test]
    fn health_is_ordered_worst_first() {
        assert!(Health::Incompatible < Health::Unreachable);
        assert!(Health::Unreachable < Health::Unusable);
        assert!(Health::Unusable < Health::Unknown);
        assert!(Health::Unknown < Health::Ready);
    }

    #[test]
    fn any_reported_degradation_makes_a_node_unusable() {
        assert_eq!(
            Health::from_syncing_status(true, false, false),
            Health::Unusable,
        );

        assert_eq!(
            Health::from_syncing_status(false, true, false),
            Health::Unusable,
        );

        assert_eq!(
            Health::from_syncing_status(false, false, true),
            Health::Unusable,
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
            Health::Unknown,
            Health::Ready,
        ] {
            assert_eq!(Health::from_u8(health.as_u8()), health);
        }
    }
}
