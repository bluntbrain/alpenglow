// Copyright (c) Anza Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Parameters for NewCon, the MCP protocol.

/// Parameters of the NewCon protocol and its hubs.
///
/// The symbols in parentheses are the ones used in the NewCon paper.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct NewconParameters {
    /// Number of concurrent proposers per window (`k`).
    pub(crate) num_proposers: usize,
    /// Maximum one-way network delay between two members of a hub, in milliseconds (`∆local`).
    pub(crate) delta_local_ms: f64,
    /// Minimum number of members of an active hub (`n_min`).
    ///
    /// The protocol requires this to be at least [`Self::num_proposers`].
    pub(crate) min_hub_members: usize,
    /// Minimum hub stake of an active hub, as a fraction of the total stake (`ρ_min`).
    pub(crate) min_hub_stake: f64,
    /// Probability that a window is assigned proportionally to hub stake (`α`).
    ///
    /// Otherwise, the window is assigned to an active hub chosen uniformly at random.
    pub(crate) stake_weighted_windows: f64,
}

impl NewconParameters {
    /// Parameters suggested in the NewCon paper (Table 1 and Section 3.1).
    pub(crate) const PAPER: Self = Self {
        num_proposers: 3,
        delta_local_ms: 10.0,
        min_hub_members: 3,
        min_hub_stake: 0.01,
        stake_weighted_windows: 0.5,
    };
}
