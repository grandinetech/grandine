use futures::{
    channel::mpsc::{TrySendError, UnboundedSender},
    sink::Drain,
};

pub trait UnboundedSink<T>: Send + 'static {
    // This is needed because `Drain` does not implement `Clone`.
    fn clone(&self) -> Self;

    fn unbounded_send(&self, message: T) -> Result<(), T>;
}

impl<T, S: UnboundedSink<T> + Clone> UnboundedSink<T> for Option<S> {
    fn clone(&self) -> Self {
        Clone::clone(self)
    }

    fn unbounded_send(&self, message: T) -> Result<(), T> {
        match self {
            Some(sink) => sink.unbounded_send(message),
            None => Ok(()),
        }
    }
}

impl<T: Send + 'static> UnboundedSink<T> for UnboundedSender<T> {
    fn clone(&self) -> Self {
        Clone::clone(self)
    }

    fn unbounded_send(&self, message: T) -> Result<(), T> {
        self.unbounded_send(message)
            .map_err(TrySendError::into_inner)
    }
}

impl<T: Send + 'static> UnboundedSink<T> for Drain<T> {
    fn clone(&self) -> Self {
        futures::sink::drain()
    }

    fn unbounded_send(&self, _message: T) -> Result<(), T> {
        Ok(())
    }
}
