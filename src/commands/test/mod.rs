// src/commands/test/mod.rs
//
// Test command module - coordinates all test execution components

mod guest;
mod packet;
pub(crate) mod runner;
mod setup;
mod trace;
mod validation;

// Re-export the main test handler
pub use runner::handle_test;
