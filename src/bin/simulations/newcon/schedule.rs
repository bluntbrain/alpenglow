// Copyright (c) Anza Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Proposer schedule of NewCon.
//!
//! Implements the proposer schedule of the NewCon paper (Algorithm 3), for
//! sampling single windows. Every window is assigned to an active hub, and its
//! `k` proposers are drawn among the members of this hub, according to their
//! proposer stake.
//!
//! The paper additionally reorders the windows such that consecutive windows
//! stay within one region (SIMD-0675). The order of the windows does not matter
//! for the analyses here, so this step is left out.

use rand::prelude::*;

use super::hubs::{Hub, window_shares};
use super::parameters::NewconParameters;

/// Proposer schedule for a set of hubs.
pub(crate) struct ProposerSchedule {
    /// Number of proposers per window.
    num_proposers: usize,
    /// The active hubs, which take part in the schedule.
    hubs: Vec<ScheduledHub>,
}

/// An active hub in the proposer schedule.
struct ScheduledHub {
    /// Index of the hub in the list of hubs that the schedule was created from.
    index: usize,
    /// Share of all windows that are assigned to this hub.
    window_share: f64,
    /// Cap on the proposer stake of a single member.
    cap: f64,
    /// Proposer stakes of the members.
    proposer_stakes: Vec<f64>,
}

/// The proposers of a single window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Window {
    /// Index of the hub in the list of hubs that the schedule was created from.
    pub(crate) hub: usize,
    /// The proposers, as indices into the members of the hub.
    pub(crate) proposers: Vec<usize>,
}

impl ProposerSchedule {
    /// Creates the proposer schedule for the active hubs among `hubs`.
    pub(crate) fn new(hubs: &[Hub], params: &NewconParameters) -> Self {
        let num_proposers = params.num_proposers;
        let (indices, active_hubs): (Vec<usize>, Vec<&Hub>) = hubs
            .iter()
            .enumerate()
            .filter(|(_, hub)| hub.is_active(params))
            .unzip();
        let shares = window_shares(&active_hubs, params);
        let hubs = indices
            .into_iter()
            .zip(active_hubs)
            .zip(shares)
            .map(|((index, hub), window_share)| ScheduledHub {
                index,
                window_share,
                cap: hub.hub_stake(num_proposers) / num_proposers as f64,
                proposer_stakes: hub.proposer_stakes(num_proposers),
            })
            .collect();
        Self {
            num_proposers,
            hubs,
        }
    }

    /// Number of proposers per window.
    pub(crate) fn num_proposers(&self) -> usize {
        self.num_proposers
    }

    /// Gives the share of all windows that are assigned to the hub with the given index.
    ///
    /// Returns zero for hubs that are not active.
    pub(crate) fn window_share(&self, hub: usize) -> f64 {
        self.scheduled(hub).map_or(0.0, |hub| hub.window_share)
    }

    /// Gives the probability that the given member is a proposer in a window of its hub.
    ///
    /// Returns zero for members of hubs that are not active.
    pub(crate) fn seat_probability(&self, hub: usize, member: usize) -> f64 {
        self.scheduled(hub)
            .map_or(0.0, |hub| hub.proposer_stakes[member] / hub.cap)
    }

    /// Samples the hub and the proposers of a single window.
    ///
    /// # Panics
    ///
    /// Panics if there are no active hubs.
    pub(crate) fn sample_window(&self, rng: &mut impl Rng) -> Window {
        // assign the window to a hub
        let mut share = rng.random::<f64>();
        let mut hub = self.hubs.last().expect("there should be an active hub");
        for candidate in &self.hubs {
            if share < candidate.window_share {
                hub = candidate;
                break;
            }
            share -= candidate.window_share;
        }

        // place the members on a line in random order, each covering its proposer stake,
        // and pick the members at `num_proposers` points that are one cap apart
        let mut order: Vec<usize> = (0..hub.proposer_stakes.len()).collect();
        order.shuffle(rng);
        let mut proposers = Vec::with_capacity(self.num_proposers);
        let mut point = rng.random_range(0.0..hub.cap);
        let mut end = 0.0;
        for &member in &order {
            end += hub.proposer_stakes[member];
            if point < end && proposers.len() < self.num_proposers {
                proposers.push(member);
                point += hub.cap;
            }
        }
        // the last point can miss the end of the line due to rounding errors
        for &member in order.iter().rev() {
            if proposers.len() == self.num_proposers {
                break;
            }
            if !proposers.contains(&member) {
                proposers.push(member);
            }
        }

        Window {
            hub: hub.index,
            proposers,
        }
    }

    /// Finds the active hub with the given index in the original list of hubs.
    fn scheduled(&self, hub: usize) -> Option<&ScheduledHub> {
        self.hubs.iter().find(|scheduled| scheduled.index == hub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NUM_WINDOWS: usize = 100_000;
    /// Tolerance for sampled frequencies, about 6 standard deviations at 50%.
    const TOLERANCE: f64 = 0.01;

    fn hub(stakes: &[f64]) -> Hub {
        Hub::new("test".to_owned(), stakes.to_vec())
    }

    /// Counts how often each member of each hub is a proposer.
    fn count_seats(schedule: &ProposerSchedule, hubs: &[Hub]) -> Vec<Vec<usize>> {
        let mut rng = StdRng::seed_from_u64(42);
        let mut seats: Vec<Vec<usize>> = hubs.iter().map(|h| vec![0; h.num_members()]).collect();
        for _ in 0..NUM_WINDOWS {
            let window = schedule.sample_window(&mut rng);
            // the proposers of a window are distinct members of the same hub
            assert_eq!(window.proposers.len(), schedule.num_proposers());
            for (i, proposer) in window.proposers.iter().enumerate() {
                assert!(!window.proposers[..i].contains(proposer));
                seats[window.hub][*proposer] += 1;
            }
        }
        seats
    }

    #[test]
    fn proposers_paper_example() {
        // Section 3.1: the two largest members are proposers in every window, the third
        // proposer is one of the two small members, in 60% and 40% of the windows
        let hubs = [hub(&[0.06, 0.02, 0.012, 0.008])];
        let schedule = ProposerSchedule::new(&hubs, &NewconParameters::PAPER);
        let seats = count_seats(&schedule, &hubs);
        assert_eq!(seats[0][0], NUM_WINDOWS);
        assert_eq!(seats[0][1], NUM_WINDOWS);
        assert!((seats[0][2] as f64 / NUM_WINDOWS as f64 - 0.6).abs() < TOLERANCE);
        assert!((seats[0][3] as f64 / NUM_WINDOWS as f64 - 0.4).abs() < TOLERANCE);
    }

    #[test]
    fn seats_match_seat_probabilities() {
        let hubs = [
            hub(&[0.05, 0.04, 0.03, 0.02, 0.01]),
            hub(&[0.001; 2]), // not active, too few members
            hub(&[0.02, 0.01, 0.01, 0.005]),
        ];
        let schedule = ProposerSchedule::new(&hubs, &NewconParameters::PAPER);
        assert_eq!(schedule.window_share(1), 0.0);
        assert_eq!(schedule.seat_probability(1, 0), 0.0);
        let total_share = schedule.window_share(0) + schedule.window_share(2);
        assert!((total_share - 1.0).abs() < 1e-12);

        let seats = count_seats(&schedule, &hubs);
        for (hub, hub_seats) in seats.iter().enumerate() {
            // every window has `k` proposers
            let windows = hub_seats.iter().sum::<usize>() as f64 / 3.0 / NUM_WINDOWS as f64;
            assert!((windows - schedule.window_share(hub)).abs() < TOLERANCE);
            for (member, member_seats) in hub_seats.iter().enumerate() {
                let sampled = *member_seats as f64 / NUM_WINDOWS as f64;
                let expected = schedule.window_share(hub) * schedule.seat_probability(hub, member);
                assert!((sampled - expected).abs() < TOLERANCE);
            }
        }
    }

    #[test]
    fn single_proposer_is_stake_weighted() {
        // with one proposer and purely stake-weighted windows, this is a leader schedule
        let params = NewconParameters {
            num_proposers: 1,
            min_hub_members: 1,
            stake_weighted_windows: 1.0,
            ..NewconParameters::PAPER
        };
        let hubs = [hub(&[0.3, 0.1]), hub(&[0.4, 0.2])];
        let schedule = ProposerSchedule::new(&hubs, &params);
        let seats = count_seats(&schedule, &hubs);
        for (hub, hub_seats) in seats.iter().enumerate() {
            for (member, member_seats) in hub_seats.iter().enumerate() {
                let sampled = *member_seats as f64 / NUM_WINDOWS as f64;
                assert!((sampled - hubs[hub].stakes()[member]).abs() < TOLERANCE);
            }
        }
    }
}
