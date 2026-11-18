// Copyright (c) Anza Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Incentive to split a hub in NewCon.
//!
//! In the hub schedule of NewCon, only a fraction `α` of the windows is assigned
//! by hub stake. The rest is shared evenly among the active hubs. This keeps a
//! large hub from dominating the schedule, and stake in a small hub earns more
//! windows than stake in a large one.
//!
//! However, a hub is just a registered name, and nothing ties it to a place.
//! The members of a large hub do not have to move to earn more windows: they
//! can register more hubs right where they are, and spread out over them.
//! This analysis measures how many windows the largest hub gains by doing so.

use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use log::info;

use super::coverage::mainnet_hubs;
use super::hubs::{Hub, window_shares};
use super::parameters::NewconParameters;

/// Values of `α` to evaluate, the paper suggests 0.5.
const STAKE_WEIGHTED_WINDOWS: [f64; 5] = [0.0, 0.25, 0.5, 0.75, 1.0];
/// Numbers of hubs that the largest hub splits into.
const PARTS: [usize; 8] = [1, 2, 3, 5, 10, 20, 30, 50];

/// Runs the hub splitting analysis on the Solana mainnet stake distribution.
///
/// Writes the results to `data/output/simulations/newcon/hub_splitting.csv`.
pub(crate) fn run_hub_splitting_analysis() -> Result<()> {
    let hubs = mainnet_hubs(NewconParameters::PAPER.delta_local_ms);

    let path = PathBuf::from("data")
        .join("output")
        .join("simulations")
        .join("newcon")
        .join("hub_splitting")
        .with_extension("csv");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut writer = csv::Writer::from_writer(File::create(path)?);
    writer.write_record([
        "stake_weighted_windows",
        "hub",
        "hub_stake_share",
        "parts",
        "window_share",
    ])?;

    for stake_weighted_windows in STAKE_WEIGHTED_WINDOWS {
        let params = NewconParameters {
            stake_weighted_windows,
            ..NewconParameters::PAPER
        };
        let num_proposers = params.num_proposers;
        let active_hubs: Vec<&Hub> = hubs.iter().filter(|hub| hub.is_active(&params)).collect();
        let hub_stake = |hub: &&Hub| hub.hub_stake(num_proposers);
        let Some(largest) = (0..active_hubs.len())
            .max_by(|&a, &b| hub_stake(&active_hubs[a]).total_cmp(&hub_stake(&active_hubs[b])))
        else {
            continue;
        };
        let total_hub_stake: f64 = active_hubs.iter().map(hub_stake).sum();
        let hub_stake_share = hub_stake(&active_hubs[largest]) / total_hub_stake;

        for parts in PARTS {
            let Some(window_share) =
                window_share_after_split(&active_hubs, largest, parts, &params)
            else {
                continue;
            };
            info!(
                "newcon hub split (α={stake_weighted_windows}, parts={parts}): \
                {} has {:.1}% of the hub stake, and gets {:.1}% of windows",
                active_hubs[largest].name,
                hub_stake_share * 100.0,
                window_share * 100.0,
            );
            writer.write_record([
                stake_weighted_windows.to_string(),
                active_hubs[largest].name.clone(),
                hub_stake_share.to_string(),
                parts.to_string(),
                window_share.to_string(),
            ])?;
        }
    }
    writer.flush()?;

    Ok(())
}

/// Calculates the share of all windows a hub gets in total, if it splits into `parts` hubs.
///
/// Here, `hub` is the index of the hub that splits among the given active hubs.
/// Returns `None` if not all of the resulting hubs would be active.
fn window_share_after_split(
    active_hubs: &[&Hub],
    hub: usize,
    parts: usize,
    params: &NewconParameters,
) -> Option<f64> {
    let split = active_hubs[hub].split(parts);
    if !split.iter().all(|part| part.is_active(params)) {
        return None;
    }
    let others = active_hubs
        .iter()
        .enumerate()
        .filter(|(other, _)| *other != hub)
        .map(|(_, other)| *other);
    let all_hubs: Vec<&Hub> = split.iter().chain(others).collect();
    let shares = window_shares(&all_hubs, params);
    Some(shares[..parts].iter().sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPSILON: f64 = 1e-9;

    /// A large hub with 80% of the stake and two small ones with 10% each.
    fn test_hubs() -> Vec<Hub> {
        vec![
            Hub::new("small1".to_owned(), vec![0.01; 10]),
            Hub::new("large".to_owned(), vec![0.01; 80]),
            Hub::new("small2".to_owned(), vec![0.01; 10]),
        ]
    }

    fn share_after_split(parts: usize, stake_weighted_windows: f64) -> Option<f64> {
        let hubs = test_hubs();
        let active_hubs: Vec<&Hub> = hubs.iter().collect();
        let params = NewconParameters {
            stake_weighted_windows,
            ..NewconParameters::PAPER
        };
        window_share_after_split(&active_hubs, 1, parts, &params)
    }

    #[test]
    fn splitting_gains_windows() {
        // as one hub: half of the windows by stake (80%), the other half evenly (1 of 3)
        let share = share_after_split(1, 0.5).unwrap();
        assert!((share - (0.4 + 0.5 / 3.0)).abs() < EPSILON);
        // as two hubs: the same by stake, but 2 of 4 hubs in the even half
        let share = share_after_split(2, 0.5).unwrap();
        assert!((share - (0.4 + 0.5 / 2.0)).abs() < EPSILON);
        // as eight hubs: 8 of 10 hubs in the even half, as much as its stake
        let share = share_after_split(8, 0.5).unwrap();
        assert!((share - 0.8).abs() < EPSILON);
        // as twenty hubs: more than its stake
        let share = share_after_split(20, 0.5).unwrap();
        assert!(share > 0.85);
    }

    #[test]
    fn splitting_gains_nothing_if_purely_stake_weighted() {
        for parts in [1, 2, 8, 20] {
            let share = share_after_split(parts, 1.0).unwrap();
            assert!((share - 0.8).abs() < EPSILON);
        }
    }

    #[test]
    fn cannot_split_below_minimum_hub_size() {
        // 27 hubs would leave one of them with fewer than three members
        assert!(share_after_split(26, 0.5).is_some());
        assert_eq!(share_after_split(27, 0.5), None);
    }
}
