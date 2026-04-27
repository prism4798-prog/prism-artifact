//! All the protocol implementations.

use crate::{
    channels::ChannelError, commitments::CommitmentError,
    protocols::hash_to_prime::HashToPrimeError,
};
use ark_relations::r1cs::SynthesisError;
use rug::Integer;


pub mod hash_to_prime;
pub mod membership;
pub mod modeq;
pub mod root;
pub mod zkauth;

quick_error! {
    #[derive(Debug)]
    pub enum CRSError {
        InvalidParameters {}
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum SetupError {
        CouldNotPerformSetup {}
        SNARKError(err: SynthesisError) {
            from()
        }
        LegoGroth16Error(err: legogroth16::error::Error) {
            from()
        }
    }
}

#[cfg(feature = "dalek")]
type R1CSError = bulletproofs::r1cs::R1CSError;

#[cfg(feature = "arkworks")]
quick_error! {
    #[derive(Debug)]
    pub enum DummyBPError {}
}
#[cfg(feature = "arkworks")]
type R1CSError = DummyBPError;

quick_error! {
    #[derive(Debug)]
    pub enum ProofError {
        CouldNotCreateProof {}
        CommitmentError(err: CommitmentError) {
            from()
        }
        IntegerError(err: Integer) {
            from()
        }
        SNARKError(err: SynthesisError) {
            from()
        }
        LegoGroth16Error(err: legogroth16::error::Error) {
            from()
        }
        VerifierChannelError(err: ChannelError) {
            from()
        }
        PrimeError(err: HashToPrimeError) {
            from()
        }
        BPError(err: R1CSError) {
            from()
        }
        CRSInitError(err: CRSError) {
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum VerificationError {
        VerificationFailed {}
        CommitmentError(err: CommitmentError) {
            from()
        }
        IntegerError(err: Integer) {
            from()
        }
        SNARKError(err: SynthesisError) {
            from()
        }
        LegoGroth16Error(err: legogroth16::error::Error) {
            from()
        }
        ProverChannelError(err: ChannelError) {
            from()
        }
        BPError(err: R1CSError) {
            from()
        }
        CRSInitError(err: CRSError) {
            from()
        }
    }
}
