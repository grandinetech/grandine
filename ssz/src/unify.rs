use crate::porcelain::SszUnify;

impl SszUnify for usize {
    #[inline]
    fn unify(&mut self, other: &Self) -> bool {
        self == other
    }
}

impl<T: SszUnify> SszUnify for [T] {
    fn unify(&mut self, other: &Self) -> bool {
        let mut equal = self.len() == other.len();

        // Do not call `Iterator::all`. It short-circuits, preventing unification of later elements.
        for (self_element, other_element) in self.iter_mut().zip(other.iter()) {
            equal &= self_element.unify(other_element);
        }

        equal
    }
}

impl<T: SszUnify> SszUnify for Option<T> {
    fn unify(&mut self, other: &Self) -> bool {
        match (self, other) {
            (Some(self_value), Some(other_value)) => self_value.unify(other_value),
            (None, None) => true,
            _ => false,
        }
    }
}
