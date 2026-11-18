// Copyright (c) Anza Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Simulations for New Constellation (NewCon), the MCP protocol.
//!
//! NewCon is one instantiation of a multiple-concurrent proposers (MCP) consensus protocol.
//! Instead of a single leader, `k` proposers each build a block in every slot,
//! and the transactions of all accepted blocks are merged into one order.
//!
//! Compared to Ryse and Pyjama, NewCon has neither a leader nor a separate set of
//! relays or attesters. Instead, the proposers of a window attest to each other's
//! timing directly. This only works if they are close to each other, so the
//! proposers of a window are always drawn from one hub: a group of validators
//! that reach each other within a small network delay `∆local`.
//!
//! So far, this module only covers the hubs:
//! - Forming hubs from a stake distribution and measured latencies.
//! - The hub rules of the paper (proposer stake, hub stake, active hubs, hub schedule).
//! - How much of the stake ends up in an active hub for different parameters.

mod coverage;
mod hubs;
mod parameters;

pub(crate) use self::coverage::run_hub_coverage_analysis;
