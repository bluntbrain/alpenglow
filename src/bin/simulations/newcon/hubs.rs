// Copyright (c) Anza Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Hubs of co-located validators for NewCon.
//!
//! The `k` proposers of a NewCon window have to reach each other within `∆local`.
//! A group of validators that do is called a hub. This module forms hubs from a
//! stake distribution and pairwise latencies, and implements the hub rules of the
//! NewCon paper (Section 3.1): proposer stake, hub stake, active hubs, and the
//! share of windows each hub gets in the hub schedule.
//!
//! Hubs are formed from sites. A [`Site`] is a group of validators at the same
//! location, which are assumed to reach each other without delay.

use super::parameters::NewconParameters;

/// A group of validators at the same location.
#[derive(Clone, Debug)]
pub(crate) struct Site {
    /// Name of the location.
    pub(crate) name: String,
    /// Stakes of the validators at this site, as fractions of the total stake.
    pub(crate) stakes: Vec<f64>,
}

impl Site {
    /// Total stake of all validators at this site.
    fn stake(&self) -> f64 {
        self.stakes.iter().sum()
    }
}

/// A group of validators that reach each other within `∆local`.
#[derive(Clone, Debug)]
pub(crate) struct Hub {
    /// Name of the hub, taken from its site with the most stake.
    pub(crate) name: String,
    /// Stakes of the members, as fractions of the total stake, in descending order.
    stakes: Vec<f64>,
}

impl Hub {
    /// Creates a hub from the stakes of its members.
    pub(crate) fn new(name: String, mut stakes: Vec<f64>) -> Self {
        stakes.sort_unstable_by(|a, b| b.total_cmp(a));
        Self { name, stakes }
    }

    /// Number of validators in this hub.
    pub(crate) fn num_members(&self) -> usize {
        self.stakes.len()
    }

    /// Total stake of all members, including any stake above the proposer cap.
    pub(crate) fn stake(&self) -> f64 {
        self.stakes.iter().sum()
    }

    /// Stake of the largest member, or zero if the hub is empty.
    pub(crate) fn largest_member_stake(&self) -> f64 {
        self.stakes.first().copied().unwrap_or(0.0)
    }

    /// Calculates the cap `c` on the proposer stake of a single member.
    ///
    /// A window needs `num_proposers` distinct proposers, so a member cannot
    /// hold more than one of these roles, however much stake it has. Its
    /// proposer stake is therefore its stake, capped at `c`. The cap is chosen
    /// such that each capped member holds exactly a `1 / num_proposers`
    /// fraction of the hub stake, and is thus a proposer in every window.
    ///
    /// Returns `None` if the hub has fewer than `num_proposers` members.
    pub(crate) fn proposer_stake_cap(&self, num_proposers: usize) -> Option<f64> {
        if num_proposers == 0 || self.stakes.len() < num_proposers {
            return None;
        }
        let mut cap = 0.0;
        for (j, &stake) in self.stakes.iter().take(num_proposers).enumerate() {
            // stake of all but the `j` largest members, split over the remaining roles
            let rest: f64 = self.stakes[j..].iter().sum();
            cap = rest / (num_proposers - j) as f64;
            if stake <= cap {
                break;
            }
        }
        Some(cap)
    }

    /// Calculates the hub stake, the sum of the proposer stakes of all members.
    ///
    /// Returns zero if the hub has fewer than `num_proposers` members.
    pub(crate) fn hub_stake(&self, num_proposers: usize) -> f64 {
        self.proposer_stake_cap(num_proposers)
            .map_or(0.0, |cap| cap * num_proposers as f64)
    }

    /// Counts the members that are a proposer in every window of this hub.
    ///
    /// These are the members with at least as much stake as the proposer cap.
    pub(crate) fn num_capped_members(&self, num_proposers: usize) -> usize {
        self.proposer_stake_cap(num_proposers).map_or(0, |cap| {
            self.stakes.iter().filter(|&&stake| stake >= cap).count()
        })
    }

    /// Checks whether this hub is active, i.e. takes part in the proposer schedule.
    ///
    /// A hub is active if it has enough members and enough hub stake. The third
    /// condition of the paper, that the members reach each other within
    /// `∆local`, holds by construction for hubs from [`form_hubs`].
    pub(crate) fn is_active(&self, params: &NewconParameters) -> bool {
        let min_members = params.min_hub_members.max(params.num_proposers);
        self.num_members() >= min_members
            && self.hub_stake(params.num_proposers) >= params.min_hub_stake
    }
}

/// Forms hubs from the given sites.
///
/// Sites can share a hub if their validators reach each other within
/// `delta_local_ms`. Here, `delay_ms(a, b)` gives the one-way network delay in
/// milliseconds between the sites with indices `a` and `b`. Within a hub, every
/// pair of sites has to be this close.
///
/// Finding the best such grouping is a hard problem (clique cover). This uses a
/// greedy heuristic that favors large hubs instead: the unassigned site with
/// the most stake starts a new hub, which then absorbs every remaining site that
/// is close enough to all sites already in the hub, again by descending stake.
///
/// Every site ends up in exactly one hub. Not all of these hubs are active.
pub(crate) fn form_hubs(
    sites: &[Site],
    delay_ms: impl Fn(usize, usize) -> f64,
    delta_local_ms: f64,
) -> Vec<Hub> {
    // site indices by descending stake, ties keep their input order
    let mut order: Vec<usize> = (0..sites.len()).collect();
    order.sort_by(|&a, &b| sites[b].stake().total_cmp(&sites[a].stake()));

    let mut assigned = vec![false; sites.len()];
    let mut hubs = Vec::new();
    for (i, &seed) in order.iter().enumerate() {
        if assigned[seed] {
            continue;
        }
        assigned[seed] = true;
        let mut hub_sites = vec![seed];
        for &candidate in &order[i + 1..] {
            let is_close = |&member: &usize| delay_ms(member, candidate) <= delta_local_ms;
            if !assigned[candidate] && hub_sites.iter().all(is_close) {
                assigned[candidate] = true;
                hub_sites.push(candidate);
            }
        }
        let stakes = hub_sites
            .iter()
            .flat_map(|&site| sites[site].stakes.iter().copied())
            .collect();
        hubs.push(Hub::new(sites[seed].name.clone(), stakes));
    }
    hubs
}

/// Calculates the share of all windows that each of the given active hubs gets.
///
/// This is the hub schedule of the paper (Algorithm 3, line 1): with probability
/// `α` ([`NewconParameters::stake_weighted_windows`]) a window is assigned
/// proportionally to hub stake, otherwise to a hub chosen uniformly at random.
/// So every active hub gets a minimum share of the windows, however small it is.
pub(crate) fn window_shares(active_hubs: &[&Hub], params: &NewconParameters) -> Vec<f64> {
    let alpha = params.stake_weighted_windows;
    let hub_stakes: Vec<f64> = active_hubs
        .iter()
        .map(|hub| hub.hub_stake(params.num_proposers))
        .collect();
    let total_hub_stake: f64 = hub_stakes.iter().sum();
    let num_hubs = active_hubs.len() as f64;
    hub_stakes
        .iter()
        .map(|hub_stake| alpha * hub_stake / total_hub_stake + (1.0 - alpha) / num_hubs)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPSILON: f64 = 1e-12;

    fn hub(stakes: &[f64]) -> Hub {
        Hub::new("test".to_owned(), stakes.to_vec())
    }

    /// Sites on a line, given as `(position in ms, total stake)`.
    fn sites_on_line(sites: &[(f64, f64)]) -> (Vec<Site>, impl Fn(usize, usize) -> f64) {
        let positions: Vec<f64> = sites.iter().map(|(position, _)| *position).collect();
        let sites = sites
            .iter()
            .enumerate()
            .map(|(i, (_, stake))| Site {
                name: format!("site{i}"),
                stakes: vec![*stake],
            })
            .collect();
        let delay_ms = move |a: usize, b: usize| (positions[a] - positions[b]).abs();
        (sites, delay_ms)
    }

    #[test]
    fn proposer_stake_paper_example() {
        // Section 3.1: with k = 3 and stakes of 6%, 2%, 1.2% and 0.8%, the cap is 2%,
        // the two largest members are proposers in every window, and the hub stake is 6%
        let hub = hub(&[0.012, 0.06, 0.008, 0.02]);
        assert!((hub.proposer_stake_cap(3).unwrap() - 0.02).abs() < EPSILON);
        assert!((hub.hub_stake(3) - 0.06).abs() < EPSILON);
        assert_eq!(hub.num_capped_members(3), 2);
        assert!((hub.stake() - 0.1).abs() < EPSILON);
        assert!((hub.largest_member_stake() - 0.06).abs() < EPSILON);
    }

    #[test]
    fn proposer_stake_without_large_members() {
        // nobody is capped, so the hub stake is simply the total stake
        let hub = hub(&[0.01; 5]);
        assert!((hub.proposer_stake_cap(3).unwrap() - 0.05 / 3.0).abs() < EPSILON);
        assert!((hub.hub_stake(3) - 0.05).abs() < EPSILON);
        assert_eq!(hub.num_capped_members(3), 0);
    }

    #[test]
    fn proposer_stake_with_exactly_k_members() {
        // all three members are proposers in every window, capped at the smallest stake
        let hub = hub(&[0.05, 0.03, 0.01]);
        assert!((hub.proposer_stake_cap(3).unwrap() - 0.01).abs() < EPSILON);
        assert!((hub.hub_stake(3) - 0.03).abs() < EPSILON);
        assert_eq!(hub.num_capped_members(3), 3);
    }

    #[test]
    fn single_proposer_is_not_capped() {
        // with k = 1 this is Alpenglow: the hub stake is the total stake
        let hub = hub(&[0.05, 0.03, 0.01]);
        assert!((hub.hub_stake(1) - 0.09).abs() < EPSILON);
        assert_eq!(hub.num_capped_members(1), 0);
    }

    #[test]
    fn too_few_members() {
        let hub = hub(&[0.3, 0.2]);
        assert_eq!(hub.proposer_stake_cap(3), None);
        assert_eq!(hub.hub_stake(3), 0.0);
        assert_eq!(hub.num_capped_members(3), 0);
        assert!(!hub.is_active(&NewconParameters::PAPER));
    }

    #[test]
    fn active_hubs() {
        let params = NewconParameters::PAPER;
        // enough members and enough hub stake
        assert!(hub(&[0.004; 3]).is_active(&params));
        // enough members, but not enough hub stake
        assert!(!hub(&[0.003; 3]).is_active(&params));
        // a lot of stake, but capped: the hub stake is only 3 * 0.2%
        assert!(!hub(&[0.3, 0.002, 0.002]).is_active(&params));
    }

    #[test]
    fn hubs_absorb_close_sites() {
        let (sites, delay_ms) =
            sites_on_line(&[(0.0, 0.05), (8.0, 0.03), (16.0, 0.02), (100.0, 0.01)]);

        // the third site is too far from the first, so it starts its own hub
        let hubs = form_hubs(&sites, &delay_ms, 10.0);
        let members: Vec<_> = hubs.iter().map(Hub::num_members).collect();
        assert_eq!(members, [2, 1, 1]);
        assert_eq!(hubs[0].name, "site0");
        assert!((hubs[0].stake() - 0.08).abs() < EPSILON);

        // with a larger `∆local`, it joins the first hub
        let hubs = form_hubs(&sites, &delay_ms, 20.0);
        let members: Vec<_> = hubs.iter().map(Hub::num_members).collect();
        assert_eq!(members, [3, 1]);

        // every site is in exactly one hub
        let total_stake: f64 = hubs.iter().map(Hub::stake).sum();
        assert!((total_stake - 0.11).abs() < EPSILON);
    }

    #[test]
    fn hub_sites_are_pairwise_close() {
        // both small sites are close to the large one, but not to each other
        let (sites, delay_ms) = sites_on_line(&[(0.0, 0.05), (8.0, 0.01), (-8.0, 0.03)]);
        let hubs = form_hubs(&sites, &delay_ms, 10.0);
        let members: Vec<_> = hubs.iter().map(Hub::num_members).collect();
        assert_eq!(members, [2, 1]);
        // the larger of the two small sites wins the spot in the hub
        assert!((hubs[0].stake() - 0.08).abs() < EPSILON);
        assert_eq!(hubs[1].name, "site1");
    }

    #[test]
    fn window_shares_mix_stake_and_uniform() {
        let params = NewconParameters::PAPER;
        let large = hub(&[0.02; 3]);
        let small = hub(&[0.02 / 3.0; 3]);
        let shares = window_shares(&[&large, &small], &params);
        // half of the windows by hub stake (3:1), the other half evenly
        assert!((shares[0] - 0.625).abs() < EPSILON);
        assert!((shares[1] - 0.375).abs() < EPSILON);

        // purely stake-weighted
        let params = NewconParameters {
            stake_weighted_windows: 1.0,
            ..params
        };
        let shares = window_shares(&[&large, &small], &params);
        assert!((shares[0] - 0.75).abs() < EPSILON);
        assert!((shares[1] - 0.25).abs() < EPSILON);
    }
}
