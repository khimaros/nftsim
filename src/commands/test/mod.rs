// test command: boots a UML guest, injects packets, and checks the traces

pub mod embedded;
mod guest;
mod packet;
pub(crate) mod report;
pub(crate) mod runner;
mod setup;
mod trace;
mod validation;

pub use runner::handle_test;
