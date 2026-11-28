//! A fixed-output random number generator, shared by the test modules.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng, utils};

/// An RNG that returns the bytes it was given, in order. Test helper only; panics once the
/// bytes run out.
pub(crate) struct FixedRng {
    /// The bytes still to be returned.
    pub(crate) bytes: Vec<u8>,
}

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert!(dst.len() <= self.bytes.len(), "FixedRng ran out of bytes");
        dst.copy_from_slice(&self.bytes[..dst.len()]);
        self.bytes.drain(..dst.len());
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}
