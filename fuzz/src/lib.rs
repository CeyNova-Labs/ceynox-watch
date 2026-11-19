//! The parsers under test, compiled straight from the program's sources.
//!
//! ceynox-watch is a binary with no library to link against, so the files
//! are included by path, laid out as they are there (`crate::event`,
//! `crate::sensor::dns`) so that their own `use` lines resolve unchanged.
//! Only part of each file is exercised from here, hence the allowance.
#![allow(dead_code, unused_imports)]

#[path = "../../crates/ceynox-watch/src/event.rs"]
pub mod event;

pub mod sensor;
