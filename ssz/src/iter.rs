use core::iter::FusedIterator;

use derive_more::Constructor;

pub struct UpTo3<T>(Option<T>, Option<T>, Option<T>);

impl<T> From<T> for UpTo3<T> {
    fn from(item1: T) -> Self {
        Self(Some(item1), None, None)
    }
}

impl<T> From<[T; 2]> for UpTo3<T> {
    fn from([item1, item2]: [T; 2]) -> Self {
        Self(Some(item1), Some(item2), None)
    }
}

impl<T> From<[T; 3]> for UpTo3<T> {
    fn from([item1, item2, item3]: [T; 3]) -> Self {
        Self(Some(item1), Some(item2), Some(item3))
    }
}

impl<T> Iterator for UpTo3<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let Self(option1, option2, option3) = self;
        option1
            .take()
            .or_else(|| option2.take())
            .or_else(|| option3.take())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let Self(option1, option2, option3) = self;
        let length = option1.iter().len() + option2.iter().len() + option3.iter().len();
        (length, Some(length))
    }
}

impl<T> ExactSizeIterator for UpTo3<T> {}

impl<T> FusedIterator for UpTo3<T> {}

#[derive(Constructor)]
pub struct ExactSize<I> {
    inner: I,
    size: usize,
}

impl<I: Iterator> Iterator for ExactSize<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next()?;
        self.size -= 1;
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.size, Some(self.size))
    }

    fn count(self) -> usize {
        self.inner.count()
    }

    fn last(self) -> Option<Self::Item> {
        self.inner.last()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.inner.nth(n)
    }

    fn fold<B, F: FnMut(B, Self::Item) -> B>(self, init: B, f: F) -> B {
        self.inner.fold(init, f)
    }

    fn max(self) -> Option<Self::Item>
    where
        Self::Item: Ord,
    {
        self.inner.max()
    }

    fn min(self) -> Option<Self::Item>
    where
        Self::Item: Ord,
    {
        self.inner.min()
    }
}

impl<T: DoubleEndedIterator> DoubleEndedIterator for ExactSize<T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let item = self.inner.next_back()?;
        self.size -= 1;
        Some(item)
    }

    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.inner.nth_back(n)
    }

    fn rfold<B, F: FnMut(B, Self::Item) -> B>(self, init: B, f: F) -> B where {
        self.inner.rfold(init, f)
    }
}

impl<T: Iterator> ExactSizeIterator for ExactSize<T> {}

impl<T: FusedIterator> FusedIterator for ExactSize<T> {}
