// Copyright (c) Anza Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Hub coverage analysis for NewCon.
//!
//! Only validators in an active hub can be proposers in NewCon, all others only
//! vote. This analysis forms hubs from the Solana mainnet stake distribution,
//! and reports how much of the stake would not be part of any active hub, for a
//! range of `∆local` and `ρ_min`.
//!
//! This mirrors Table 2 of the NewCon paper, with one difference. For lack of
//! latency measurements between validators, the paper approximates `∆local` by
//! distance. Here, the ping dataset of the latency simulations is used instead:
//! every validator is mapped to its closest ping server, and all validators
//! mapped to the same server form one site.
//!
//! Two definitions of a usable hub are evaluated side by side:
//! - The pair rule behind Table 2: at least two validators, which together hold
//!   at least `ρ_min` of the stake.
//! - The protocol rule of Section 3.1: at least `k` validators, with a hub stake
//!   of at least `ρ_min`. The hub stake caps the stake of large members.

use std::fs::File;
use std::path::PathBuf;

use alpenglow::network::simulated::ping_data::{PingServer, get_ping};
use alpenglow::network::simulated::stake_distribution::{
    VALIDATOR_DATA, validators_from_validator_data,
};
use alpenglow::{Stake, ValidatorInfo};
use anyhow::Result;
use log::info;

use super::hubs::{Hub, Site, form_hubs, window_shares};
use super::parameters::NewconParameters;

/// Values of `∆local` to evaluate, in milliseconds (same as in Table 2 of the paper).
const DELTA_LOCALS_MS: [f64; 4] = [2.0, 5.0, 10.0, 25.0];
/// Values of `ρ_min` to evaluate (same as in Table 2 of the paper).
const MIN_HUB_STAKES: [f64; 8] = [0.001, 0.005, 0.01, 0.02, 0.03, 0.05, 0.075, 0.1];

/// Runs the hub coverage analysis on the Solana mainnet stake distribution.
///
/// Writes two files to `data/output/simulations/newcon/`:
/// - `hub_coverage.csv`: stake outside of any hub, for all parameter combinations.
/// - `hubs.csv`: the hubs with at least `ρ_min` stake, for the parameters suggested in the paper.
pub(crate) fn run_hub_coverage_analysis() -> Result<()> {
    let (_, validators) = validators_from_validator_data(&VALIDATOR_DATA);
    let (sites, servers) = sites_from_validators(&validators);
    let delay_ms = |a: usize, b: usize| one_way_delay_ms(servers[a], servers[b]);

    let output_dir = PathBuf::from("data")
        .join("output")
        .join("simulations")
        .join("newcon");
    std::fs::create_dir_all(&output_dir)?;

    // stake outside of any hub, for all parameter combinations
    let file = File::create(output_dir.join("hub_coverage.csv"))?;
    let mut writer = csv::Writer::from_writer(file);
    writer.write_record([
        "delta_local_ms",
        "min_hub_stake",
        "pair_rule_hubs",
        "pair_rule_uncovered_stake",
        "protocol_rule_hubs",
        "protocol_rule_uncovered_stake",
    ])?;
    for delta_local_ms in DELTA_LOCALS_MS {
        let hubs = form_hubs(&sites, delay_ms, delta_local_ms);
        for min_hub_stake in MIN_HUB_STAKES {
            let params = NewconParameters {
                delta_local_ms,
                min_hub_stake,
                ..NewconParameters::PAPER
            };
            let (pair_hubs, pair_uncovered) = uncovered_stake(&hubs, |hub| {
                hub.num_members() >= 2 && hub.stake() >= min_hub_stake
            });
            let (protocol_hubs, protocol_uncovered) =
                uncovered_stake(&hubs, |hub| hub.is_active(&params));
            info!(
                "newcon hubs (∆local={delta_local_ms}ms, ρ_min={:.1}%): \
                {:.1}% of stake not in a hub by the pair rule ({pair_hubs} hubs), \
                {:.1}% by the protocol rule ({protocol_hubs} hubs)",
                min_hub_stake * 100.0,
                pair_uncovered * 100.0,
                protocol_uncovered * 100.0,
            );
            writer.write_record([
                delta_local_ms.to_string(),
                min_hub_stake.to_string(),
                pair_hubs.to_string(),
                pair_uncovered.to_string(),
                protocol_hubs.to_string(),
                protocol_uncovered.to_string(),
            ])?;
        }
    }
    writer.flush()?;

    // the hubs for the parameters suggested in the paper
    let params = NewconParameters::PAPER;
    let num_proposers = params.num_proposers;
    let mut hubs = form_hubs(&sites, delay_ms, params.delta_local_ms);
    hubs.sort_by(|a, b| b.stake().total_cmp(&a.stake()));
    let active_hubs: Vec<&Hub> = hubs.iter().filter(|hub| hub.is_active(&params)).collect();
    let mut shares = window_shares(&active_hubs, &params).into_iter();
    let file = File::create(output_dir.join("hubs.csv"))?;
    let mut writer = csv::Writer::from_writer(file);
    writer.write_record([
        "hub",
        "members",
        "capped_members",
        "stake",
        "largest_member_stake",
        "hub_stake",
        "active",
        "window_share",
    ])?;
    // also list hubs that only fail the protocol rule, they get no windows
    let has_enough_stake = |hub: &&Hub| hub.stake() >= params.min_hub_stake;
    for hub in hubs.iter().filter(has_enough_stake) {
        let is_active = hub.is_active(&params);
        let share = if is_active {
            shares.next().unwrap_or(0.0)
        } else {
            0.0
        };
        info!(
            "newcon hub {} ({}): {} members ({} in every window), {:.2}% of stake \
            (largest member {:.2}%), {:.2}% hub stake, {:.2}% of windows",
            hub.name,
            if is_active { "active" } else { "not active" },
            hub.num_members(),
            hub.num_capped_members(num_proposers),
            hub.stake() * 100.0,
            hub.largest_member_stake() * 100.0,
            hub.hub_stake(num_proposers) * 100.0,
            share * 100.0,
        );
        writer.write_record([
            hub.name.clone(),
            hub.num_members().to_string(),
            hub.num_capped_members(num_proposers).to_string(),
            hub.stake().to_string(),
            hub.largest_member_stake().to_string(),
            hub.hub_stake(num_proposers).to_string(),
            is_active.to_string(),
            share.to_string(),
        ])?;
    }
    writer.flush()?;

    Ok(())
}

/// Forms hubs from the Solana mainnet stake distribution and the ping dataset.
pub(crate) fn mainnet_hubs(delta_local_ms: f64) -> Vec<Hub> {
    let (_, validators) = validators_from_validator_data(&VALIDATOR_DATA);
    hubs_from_validators(&validators, delta_local_ms)
}

/// Forms hubs from the given validators and their ping servers.
///
/// The hubs refer to their members by the IDs of the given validators.
pub(crate) fn hubs_from_validators(
    validators: &[(ValidatorInfo, &'static PingServer)],
    delta_local_ms: f64,
) -> Vec<Hub> {
    let (sites, servers) = sites_from_validators(validators);
    let delay_ms = |a: usize, b: usize| one_way_delay_ms(servers[a], servers[b]);
    form_hubs(&sites, delay_ms, delta_local_ms)
}

/// Groups validators into sites, one per ping server.
///
/// Returns the sites and the ping server of each site, in matching order.
/// Stakes are fractions of the total stake of the given validators.
fn sites_from_validators(
    validators: &[(ValidatorInfo, &'static PingServer)],
) -> (Vec<Site>, Vec<&'static PingServer>) {
    let total_stake: Stake = validators.iter().map(|(v, _)| v.stake).sum();
    let mut sites: Vec<Site> = Vec::new();
    let mut servers: Vec<&'static PingServer> = Vec::new();
    for (validator, server) in validators {
        let stake = validator.stake.inner() as f64 / total_stake.inner() as f64;
        if let Some(site) = servers.iter().position(|s| s.id == server.id) {
            sites[site].stakes.push(stake);
            sites[site].validators.push(validator.id);
        } else {
            servers.push(server);
            sites.push(Site {
                name: server.location.clone(),
                stakes: vec![stake],
                validators: vec![validator.id],
            });
        }
    }
    (sites, servers)
}

/// Gives the one-way network delay between two ping servers, in milliseconds.
///
/// Takes the slower of the two directions, since hub members need to reach each other.
fn one_way_delay_ms(a: &PingServer, b: &PingServer) -> f64 {
    let rtt_ms = |from: &PingServer, to: &PingServer| {
        get_ping(from.id, to.id).expect("ping data should exist for all validator pairs")
    };
    rtt_ms(a, b).max(rtt_ms(b, a)) / 2.0
}

/// Counts the hubs that satisfy `is_usable`, and sums up the stake outside of them.
fn uncovered_stake(hubs: &[Hub], is_usable: impl Fn(&Hub) -> bool) -> (usize, f64) {
    let usable: Vec<&Hub> = hubs.iter().filter(|hub| is_usable(hub)).collect();
    let covered_stake: f64 = usable.iter().map(|hub| hub.stake()).sum();
    (usable.len(), (1.0 - covered_stake).max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPSILON: f64 = 1e-9;

    #[test]
    fn every_validator_is_in_exactly_one_hub() {
        let (_, validators) = validators_from_validator_data(&VALIDATOR_DATA);
        let (sites, servers) = sites_from_validators(&validators);
        let delay_ms = |a: usize, b: usize| one_way_delay_ms(servers[a], servers[b]);

        for delta_local_ms in DELTA_LOCALS_MS {
            let hubs = form_hubs(&sites, delay_ms, delta_local_ms);
            let members: usize = hubs.iter().map(Hub::num_members).sum();
            let stake: f64 = hubs.iter().map(Hub::stake).sum();
            assert_eq!(members, validators.len());
            assert!((stake - 1.0).abs() < EPSILON);

            // without any requirements, all stake is covered
            let (num_hubs, uncovered) = uncovered_stake(&hubs, |_| true);
            assert_eq!(num_hubs, hubs.len());
            assert!(uncovered < EPSILON);
        }
    }

    #[test]
    fn protocol_rule_is_stricter_than_pair_rule() {
        let (_, validators) = validators_from_validator_data(&VALIDATOR_DATA);
        let (sites, servers) = sites_from_validators(&validators);
        let delay_ms = |a: usize, b: usize| one_way_delay_ms(servers[a], servers[b]);

        let params = NewconParameters::PAPER;
        let hubs = form_hubs(&sites, delay_ms, params.delta_local_ms);
        let (_, pair_uncovered) = uncovered_stake(&hubs, |hub| {
            hub.num_members() >= 2 && hub.stake() >= params.min_hub_stake
        });
        let (_, protocol_uncovered) = uncovered_stake(&hubs, |hub| hub.is_active(&params));
        assert!(protocol_uncovered >= pair_uncovered);
    }
}
