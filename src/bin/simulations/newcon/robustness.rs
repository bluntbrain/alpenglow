// Copyright (c) Anza Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Robustness of NewCon windows against faulty proposers.
//!
//! The `k` proposers of a NewCon window have to agree on which of them were on
//! time. This analysis asks what faulty proposers can do to a window in the
//! worst case, and how often they get the chance:
//! - Skip: nothing is included in the window. Either the adversary can force
//!   this, or too many proposers crashed.
//! - Capture: only blocks of the adversary are included in the window, so the
//!   adversary alone decides which transactions make it, and in which order.
//! - Lost capacity: the fraction of the proposer blocks of the window that are
//!   not blocks of correct proposers that end up being included.
//!
//! With a single leader per window, drawn by stake, a faulty leader affects
//! exactly its own windows. All three numbers then equal the corrupted stake
//! (except that crashed leaders capture nothing). The corrupted stake is thus
//! the baseline to compare against.
//!
//! The paper discusses three ways for the proposers to agree, see [`DecisionRule`].
//! Which validators are corrupted is up to the adversary, see [`AdversaryStrategy`].
//!
//! Like the other robustness simulations, this runs on the Solana mainnet stake
//! distribution, with hubs formed from the ping dataset.

use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use log::info;
use rand::prelude::*;
use rayon::prelude::*;

use super::coverage::mainnet_hubs;
use super::hubs::Hub;
use super::parameters::NewconParameters;
use super::schedule::ProposerSchedule;

/// Decision rules and numbers of proposers to evaluate.
const CONFIGURATIONS: [(DecisionRule, usize); 5] = [
    (DecisionRule::Unanimous, 3),
    (DecisionRule::Lanes, 3),
    (DecisionRule::Unanimous, 5),
    (DecisionRule::LocalAgreement, 5),
    (DecisionRule::Lanes, 5),
];
/// Kinds of faults to evaluate.
const FAULTS: [Fault; 2] = [Fault::Byzantine, Fault::Crashed];
/// Adversary strategies to evaluate.
const STRATEGIES: [AdversaryStrategy; 4] = [
    AdversaryStrategy::Random,
    AdversaryStrategy::CheapestSeats,
    AdversaryStrategy::WholeHubs,
    AdversaryStrategy::OwnHubs,
];
/// Fractions of the total stake that the adversary may corrupt.
const STRENGTHS: [f64; 4] = [0.01, 0.05, 0.1, 0.2];
/// Number of windows to sample per combination of the above.
const NUM_WINDOWS: u64 = 200_000;
/// Number of different sets of corrupted validators to sample for [`AdversaryStrategy::Random`].
const NUM_RANDOM_CORRUPTIONS: u64 = 20;
/// Tolerance when comparing stake against the budget of the adversary.
const BUDGET_TOLERANCE: f64 = 1e-12;

/// How the proposers of a window agree on the set of accepted proposer blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecisionRule {
    /// NewCon as specified in the paper (Section 2.3).
    ///
    /// The attestations of all accepted proposers have to agree, and the
    /// accepted proposers have to be a strict majority. So a single Byzantine
    /// proposer can make the attestations disagree, which skips the window.
    Unanimous,
    /// The proposers run a local agreement protocol (Section 4.1).
    ///
    /// More than two thirds of the proposers decide on the accepted blocks.
    /// This tolerates a faulty minority, but lets a large enough coalition of
    /// proposers exclude the blocks of everybody else.
    LocalAgreement,
    /// Every proposer runs its own lane (Section 4.2).
    ///
    /// Every lane is decided on its own, so faulty proposers only lose their own blocks.
    Lanes,
}

/// The kind of fault of the corrupted validators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// Corrupted validators are controlled by the adversary.
    Byzantine,
    /// Corrupted validators are offline.
    Crashed,
}

/// How the adversary chooses which validators to corrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdversaryStrategy {
    /// Corrupts random validators.
    Random,
    /// Corrupts the validators that put a faulty proposer into the most windows,
    /// relative to their stake.
    ///
    /// For rules where a single faulty proposer hurts the whole window,
    /// this is a cheap way to hurt many windows.
    CheapestSeats,
    /// Corrupts all members of the hubs that get the most windows, relative to their stake.
    ///
    /// This models the outage of a hub, or an adversary that takes over a hub.
    WholeHubs,
    /// Registers new hubs of minimal size, which consist only of corrupted validators.
    ///
    /// Anybody can register a hub, and every active hub gets a minimum share of
    /// the windows. The adversary splits its stake into as many hubs as possible.
    OwnHubs,
}

/// Worst case for a single window with faulty proposers.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct WindowOutcome {
    /// Nothing may be included in this window.
    pub(crate) skipped: bool,
    /// Only blocks of Byzantine proposers may be included in this window.
    pub(crate) captured: bool,
    /// Fraction of the proposer blocks that are not included blocks of correct proposers.
    pub(crate) lost_capacity: f64,
}

/// Worst-case outcomes, aggregated over many windows.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct RobustnessStats {
    windows: u64,
    skipped: u64,
    captured: u64,
    lost_capacity: f64,
}

/// A set of corrupted validators.
struct Corruption {
    /// All hubs, including any hubs added by the adversary.
    hubs: Vec<Hub>,
    /// For every hub, which of its members are corrupted.
    corrupted: Vec<Vec<bool>>,
    /// Total stake of the corrupted validators.
    stake: f64,
}

impl DecisionRule {
    /// Returns a printable name for this rule.
    fn name(self) -> &'static str {
        match self {
            Self::Unanimous => "unanimous",
            Self::LocalAgreement => "local_agreement",
            Self::Lanes => "lanes",
        }
    }

    /// Determines the worst case for a window with `faulty` faulty proposers.
    pub(crate) fn outcome(
        self,
        num_proposers: usize,
        faulty: usize,
        fault: Fault,
    ) -> WindowOutcome {
        let correct = num_proposers - faulty;
        let byzantine = match fault {
            Fault::Byzantine => faulty,
            Fault::Crashed => 0,
        };
        let (skipped, captured) = match self {
            Self::Unanimous => {
                let majority = num_proposers / 2 + 1;
                // one Byzantine proposer suffices to make the attestations disagree,
                // and without a majority of live proposers no set of blocks is accepted
                let skipped = byzantine > 0 || correct < majority;
                // a Byzantine majority decides alone, but only if no correct proposer
                // is left, since validators wait for the attestation of every proposer
                let captured = correct == 0 && byzantine >= majority;
                (skipped, captured)
            }
            Self::LocalAgreement => {
                let quorum = 2 * num_proposers / 3 + 1;
                // the correct proposers only make progress if they are a quorum,
                // and a Byzantine quorum can exclude the blocks of everybody else
                (correct < quorum, byzantine >= quorum)
            }
            Self::Lanes => {
                // faulty proposers only affect their own lanes
                (correct == 0, correct == 0 && byzantine > 0)
            }
        };
        let lost_capacity = if skipped || captured {
            1.0
        } else {
            faulty as f64 / num_proposers as f64
        };
        WindowOutcome {
            skipped,
            captured,
            lost_capacity,
        }
    }
}

impl Fault {
    /// Returns a printable name for this kind of fault.
    fn name(self) -> &'static str {
        match self {
            Self::Byzantine => "byzantine",
            Self::Crashed => "crashed",
        }
    }
}

impl AdversaryStrategy {
    /// Returns a printable name for this strategy.
    fn name(self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::CheapestSeats => "cheapest_seats",
            Self::WholeHubs => "whole_hubs",
            Self::OwnHubs => "own_hubs",
        }
    }

    /// Chooses validators to corrupt, with a total stake of at most `budget`.
    fn corrupt(
        self,
        hubs: &[Hub],
        params: &NewconParameters,
        budget: f64,
        rng: &mut impl Rng,
    ) -> Corruption {
        if self == Self::OwnHubs {
            return corrupt_own_hubs(hubs, params, budget);
        }

        let schedule = ProposerSchedule::new(hubs, params);
        let mut corrupted: Vec<Vec<bool>> = hubs
            .iter()
            .map(|hub| vec![false; hub.num_members()])
            .collect();
        let mut stake = 0.0;

        if self == Self::WholeHubs {
            // hubs by descending windows per stake
            let mut order: Vec<usize> = (0..hubs.len()).collect();
            let windows_per_stake = |hub: usize| schedule.window_share(hub) / hubs[hub].stake();
            order.sort_by(|&a, &b| windows_per_stake(b).total_cmp(&windows_per_stake(a)));
            for hub in order {
                let hub_stake = hubs[hub].stake();
                if schedule.window_share(hub) > 0.0
                    && stake + hub_stake <= budget + BUDGET_TOLERANCE
                {
                    corrupted[hub].fill(true);
                    stake += hub_stake;
                }
            }
        } else if self == Self::Random {
            let mut order: Vec<(usize, usize)> = all_validators(hubs).collect();
            order.shuffle(rng);
            for (hub, member) in order {
                let member_stake = hubs[hub].stakes()[member];
                if stake + member_stake <= budget + BUDGET_TOLERANCE {
                    corrupted[hub][member] = true;
                    stake += member_stake;
                }
            }
        } else {
            // greedily corrupt the validator that adds the most windows with a faulty
            // proposer per stake, treating the proposers of a window as independent
            let mut candidates: Vec<(usize, usize)> = all_validators(hubs)
                .filter(|&(hub, member)| schedule.seat_probability(hub, member) > 0.0)
                .collect();
            // share of all windows that are in this hub and have no faulty proposer yet
            let mut clean_windows: Vec<f64> = (0..hubs.len())
                .map(|hub| schedule.window_share(hub))
                .collect();
            loop {
                let windows_per_stake = |&(hub, member): &(usize, usize)| {
                    let windows = clean_windows[hub] * schedule.seat_probability(hub, member);
                    windows / hubs[hub].stakes()[member]
                };
                let best = candidates
                    .iter()
                    .enumerate()
                    .filter(|(_, validator)| {
                        let member_stake = hubs[validator.0].stakes()[validator.1];
                        stake + member_stake <= budget + BUDGET_TOLERANCE
                            && windows_per_stake(validator) > 0.0
                    })
                    .max_by(|(_, a), (_, b)| windows_per_stake(a).total_cmp(&windows_per_stake(b)));
                let Some((position, &(hub, member))) = best else {
                    break;
                };
                clean_windows[hub] *= 1.0 - schedule.seat_probability(hub, member);
                corrupted[hub][member] = true;
                stake += hubs[hub].stakes()[member];
                candidates.swap_remove(position);
            }
        }

        Corruption {
            hubs: hubs.to_vec(),
            corrupted,
            stake,
        }
    }
}

impl RobustnessStats {
    /// Adds the outcome of a single window.
    fn record(&mut self, outcome: WindowOutcome) {
        self.windows += 1;
        self.skipped += u64::from(outcome.skipped);
        self.captured += u64::from(outcome.captured);
        self.lost_capacity += outcome.lost_capacity;
    }

    /// Adds the outcomes of another set of windows.
    fn merge(&mut self, other: Self) {
        self.windows += other.windows;
        self.skipped += other.skipped;
        self.captured += other.captured;
        self.lost_capacity += other.lost_capacity;
    }

    /// Fraction of windows in which nothing may be included.
    pub(crate) fn skip_rate(&self) -> f64 {
        self.skipped as f64 / self.windows as f64
    }

    /// Fraction of windows in which only blocks of the adversary may be included.
    pub(crate) fn capture_rate(&self) -> f64 {
        self.captured as f64 / self.windows as f64
    }

    /// Fraction of all proposer blocks that are not included blocks of correct proposers.
    pub(crate) fn lost_capacity(&self) -> f64 {
        self.lost_capacity / self.windows as f64
    }
}

/// Runs the window robustness analysis on the Solana mainnet stake distribution.
///
/// Writes the results to `data/output/simulations/newcon/window_robustness.csv`.
pub(crate) fn run_window_robustness_analysis() -> Result<()> {
    let hubs = mainnet_hubs(NewconParameters::PAPER.delta_local_ms);

    // evaluate all combinations in parallel
    let mut combinations = Vec::new();
    for (rule, num_proposers) in CONFIGURATIONS {
        for fault in FAULTS {
            for strategy in STRATEGIES {
                for strength in STRENGTHS {
                    combinations.push((rule, num_proposers, fault, strategy, strength));
                }
            }
        }
    }
    let results: Vec<(RobustnessStats, f64)> = combinations
        .par_iter()
        .map(|&(rule, num_proposers, fault, strategy, strength)| {
            let params = NewconParameters {
                num_proposers,
                min_hub_members: num_proposers,
                ..NewconParameters::PAPER
            };
            evaluate(
                &hubs,
                &params,
                rule,
                fault,
                strategy,
                strength,
                &mut rand::rng(),
            )
        })
        .collect();

    let path = PathBuf::from("data")
        .join("output")
        .join("simulations")
        .join("newcon")
        .join("window_robustness")
        .with_extension("csv");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut writer = csv::Writer::from_writer(File::create(path)?);
    writer.write_record([
        "rule",
        "num_proposers",
        "fault",
        "strategy",
        "strength",
        "corrupted_stake",
        "skip_rate",
        "capture_rate",
        "lost_capacity",
    ])?;
    for ((rule, num_proposers, fault, strategy, strength), (stats, corrupted_stake)) in
        combinations.into_iter().zip(results)
    {
        info!(
            "newcon windows ({}, k={num_proposers}, {:.0}% {}, {}): \
            {:.1}% of stake corrupted, {:.1}% skipped, {:.1}% captured, {:.1}% capacity lost",
            rule.name(),
            strength * 100.0,
            fault.name(),
            strategy.name(),
            corrupted_stake * 100.0,
            stats.skip_rate() * 100.0,
            stats.capture_rate() * 100.0,
            stats.lost_capacity() * 100.0,
        );
        writer.write_record([
            rule.name().to_owned(),
            num_proposers.to_string(),
            fault.name().to_owned(),
            strategy.name().to_owned(),
            strength.to_string(),
            corrupted_stake.to_string(),
            stats.skip_rate().to_string(),
            stats.capture_rate().to_string(),
            stats.lost_capacity().to_string(),
        ])?;
    }
    writer.flush()?;

    Ok(())
}

/// Lists all validators, as pairs of a hub and a member of this hub.
fn all_validators(hubs: &[Hub]) -> impl Iterator<Item = (usize, usize)> {
    hubs.iter()
        .enumerate()
        .flat_map(|(hub, h)| (0..h.num_members()).map(move |member| (hub, member)))
}

/// Evaluates one decision rule against one adversary.
///
/// Returns the aggregated outcomes, and the stake the adversary actually corrupted.
fn evaluate(
    hubs: &[Hub],
    params: &NewconParameters,
    rule: DecisionRule,
    fault: Fault,
    strategy: AdversaryStrategy,
    strength: f64,
    rng: &mut impl Rng,
) -> (RobustnessStats, f64) {
    // only the random strategy gives a different set of validators each time
    let repetitions = match strategy {
        AdversaryStrategy::Random => NUM_RANDOM_CORRUPTIONS,
        _ => 1,
    };
    let mut stats = RobustnessStats::default();
    let mut corrupted_stake = 0.0;
    for _ in 0..repetitions {
        let corruption = strategy.corrupt(hubs, params, strength, rng);
        let schedule = ProposerSchedule::new(&corruption.hubs, params);
        let num_windows = NUM_WINDOWS / repetitions;
        stats.merge(simulate_windows(
            &schedule,
            &corruption.corrupted,
            rule,
            fault,
            num_windows,
            rng,
        ));
        corrupted_stake += corruption.stake / repetitions as f64;
    }
    (stats, corrupted_stake)
}

/// Samples `num_windows` windows, and aggregates their worst-case outcomes.
fn simulate_windows(
    schedule: &ProposerSchedule,
    corrupted: &[Vec<bool>],
    rule: DecisionRule,
    fault: Fault,
    num_windows: u64,
    rng: &mut impl Rng,
) -> RobustnessStats {
    let mut stats = RobustnessStats::default();
    for _ in 0..num_windows {
        let window = schedule.sample_window(rng);
        let faulty = window
            .proposers
            .iter()
            .filter(|&&proposer| corrupted[window.hub][proposer])
            .count();
        stats.record(rule.outcome(schedule.num_proposers(), faulty, fault));
    }
    stats
}

/// Lets the adversary register its own hubs, with a total stake of `budget`.
///
/// Stakes are fractions of the total stake, so the existing validators are
/// diluted by the stake that the adversary adds. The adversary registers as many
/// hubs as its stake allows, each with the minimum number of members and at
/// least the minimum hub stake. Without enough stake for one hub, it does nothing.
fn corrupt_own_hubs(hubs: &[Hub], params: &NewconParameters, budget: f64) -> Corruption {
    let num_own_hubs = (budget / params.min_hub_stake + BUDGET_TOLERANCE).floor() as usize;
    if num_own_hubs == 0 {
        return Corruption {
            hubs: hubs.to_vec(),
            corrupted: hubs
                .iter()
                .map(|hub| vec![false; hub.num_members()])
                .collect(),
            stake: 0.0,
        };
    }

    let mut all_hubs: Vec<Hub> = hubs.iter().map(|hub| hub.scaled(1.0 - budget)).collect();
    let mut corrupted: Vec<Vec<bool>> = all_hubs
        .iter()
        .map(|hub| vec![false; hub.num_members()])
        .collect();
    let num_members = params.min_hub_members.max(params.num_proposers);
    let member_stake = budget / (num_own_hubs * num_members) as f64;
    for i in 0..num_own_hubs {
        all_hubs.push(Hub::new(
            format!("adversary{i}"),
            vec![member_stake; num_members],
        ));
        corrupted.push(vec![true; num_members]);
    }
    Corruption {
        hubs: all_hubs,
        corrupted,
        stake: budget,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPSILON: f64 = 1e-9;
    /// Tolerance for sampled frequencies.
    const TOLERANCE: f64 = 0.01;

    /// A large hub and three small ones, none with capped members.
    fn test_hubs() -> Vec<Hub> {
        vec![
            Hub::new("large".to_owned(), vec![0.01; 85]),
            Hub::new("small1".to_owned(), vec![0.01; 5]),
            Hub::new("small2".to_owned(), vec![0.01; 5]),
            Hub::new("small3".to_owned(), vec![0.01; 5]),
        ]
    }

    fn outcome(rule: DecisionRule, k: usize, faulty: usize, fault: Fault) -> (bool, bool, f64) {
        let outcome = rule.outcome(k, faulty, fault);
        (outcome.skipped, outcome.captured, outcome.lost_capacity)
    }

    fn evaluate_test_hubs(
        rule: DecisionRule,
        fault: Fault,
        strategy: AdversaryStrategy,
        strength: f64,
    ) -> (RobustnessStats, f64) {
        let mut rng = StdRng::seed_from_u64(42);
        let params = NewconParameters::PAPER;
        evaluate(
            &test_hubs(),
            &params,
            rule,
            fault,
            strategy,
            strength,
            &mut rng,
        )
    }

    #[test]
    fn unanimous_outcomes() {
        let rule = DecisionRule::Unanimous;
        assert_eq!(outcome(rule, 3, 0, Fault::Byzantine), (false, false, 0.0));
        // a single Byzantine proposer can skip the window, but cannot capture it
        assert_eq!(outcome(rule, 3, 1, Fault::Byzantine), (true, false, 1.0));
        assert_eq!(outcome(rule, 3, 2, Fault::Byzantine), (true, false, 1.0));
        assert_eq!(outcome(rule, 3, 3, Fault::Byzantine), (true, true, 1.0));
        // one crashed proposer only loses its own blocks, two leave no majority
        assert_eq!(
            outcome(rule, 3, 1, Fault::Crashed),
            (false, false, 1.0 / 3.0)
        );
        assert_eq!(outcome(rule, 3, 2, Fault::Crashed), (true, false, 1.0));
        // with two proposers, a single crash leaves no majority
        assert_eq!(outcome(rule, 2, 1, Fault::Crashed), (true, false, 1.0));
        // with one proposer, this is a single leader
        assert_eq!(outcome(rule, 1, 1, Fault::Byzantine), (true, true, 1.0));
        assert_eq!(outcome(rule, 1, 1, Fault::Crashed), (true, false, 1.0));
    }

    #[test]
    fn local_agreement_outcomes() {
        let rule = DecisionRule::LocalAgreement;
        // four out of five proposers are a quorum, so one fault is tolerated
        assert_eq!(outcome(rule, 5, 1, Fault::Byzantine), (false, false, 0.2));
        assert_eq!(outcome(rule, 5, 1, Fault::Crashed), (false, false, 0.2));
        assert_eq!(outcome(rule, 5, 2, Fault::Byzantine), (true, false, 1.0));
        assert_eq!(outcome(rule, 5, 2, Fault::Crashed), (true, false, 1.0));
        // a Byzantine quorum can exclude the last correct proposer
        assert_eq!(outcome(rule, 5, 4, Fault::Byzantine), (true, true, 1.0));
        // with three proposers, the quorum is all of them
        assert_eq!(outcome(rule, 3, 1, Fault::Crashed), (true, false, 1.0));
    }

    #[test]
    fn lanes_outcomes() {
        let rule = DecisionRule::Lanes;
        // faulty proposers only lose their own blocks
        assert_eq!(
            outcome(rule, 3, 1, Fault::Byzantine),
            (false, false, 1.0 / 3.0)
        );
        assert_eq!(
            outcome(rule, 3, 2, Fault::Byzantine),
            (false, false, 2.0 / 3.0)
        );
        assert_eq!(outcome(rule, 3, 3, Fault::Byzantine), (true, true, 1.0));
        assert_eq!(outcome(rule, 3, 3, Fault::Crashed), (true, false, 1.0));
    }

    #[test]
    fn no_corruption_no_damage() {
        for strategy in STRATEGIES {
            let (stats, corrupted_stake) =
                evaluate_test_hubs(DecisionRule::Unanimous, Fault::Byzantine, strategy, 0.0);
            assert_eq!(corrupted_stake, 0.0);
            assert_eq!(stats.skip_rate(), 0.0);
            assert_eq!(stats.capture_rate(), 0.0);
            assert_eq!(stats.lost_capacity(), 0.0);
        }
    }

    #[test]
    fn strategies_respect_budget() {
        let mut rng = StdRng::seed_from_u64(42);
        let hubs = test_hubs();
        let params = NewconParameters::PAPER;
        for strategy in STRATEGIES {
            for strength in STRENGTHS {
                let corruption = strategy.corrupt(&hubs, &params, strength, &mut rng);
                assert!(corruption.stake <= strength + EPSILON);
                // the reported stake matches the corrupted validators
                let stake: f64 = corruption
                    .hubs
                    .iter()
                    .zip(&corruption.corrupted)
                    .flat_map(|(hub, corrupted)| hub.stakes().iter().zip(corrupted))
                    .filter(|(_, corrupted)| **corrupted)
                    .map(|(stake, _)| stake)
                    .sum();
                assert!((stake - corruption.stake).abs() < EPSILON);
            }
        }
    }

    #[test]
    fn random_adversary() {
        // without capped members, every proposer is faulty with probability 10%,
        // almost independently, so about 1 - 0.9^3 = 27% of windows have a faulty one
        let (stats, corrupted_stake) = evaluate_test_hubs(
            DecisionRule::Unanimous,
            Fault::Byzantine,
            AdversaryStrategy::Random,
            0.1,
        );
        assert!((corrupted_stake - 0.1).abs() < EPSILON);
        // the sets of corrupted validators differ a lot, so allow for more noise
        assert!((stats.skip_rate() - 0.27).abs() < 6.0 * TOLERANCE);
        assert!(stats.capture_rate() < TOLERANCE);

        // with lanes, only the blocks of the faulty proposers are lost
        let (stats, _) = evaluate_test_hubs(
            DecisionRule::Lanes,
            Fault::Byzantine,
            AdversaryStrategy::Random,
            0.1,
        );
        assert!(stats.skip_rate() < TOLERANCE);
        assert!((stats.lost_capacity() - 0.1).abs() < 3.0 * TOLERANCE);
    }

    #[test]
    fn cheapest_seats_adversary() {
        // the small hubs get more windows per stake, so their members are corrupted
        // first, but spread out, since a second faulty proposer in a window adds little
        let mut rng = StdRng::seed_from_u64(42);
        let hubs = test_hubs();
        let params = NewconParameters::PAPER;
        let strategy = AdversaryStrategy::CheapestSeats;
        let corruption = strategy.corrupt(&hubs, &params, 0.1, &mut rng);
        let corrupted: Vec<usize> = corruption
            .corrupted
            .iter()
            .map(|hub| hub.iter().filter(|corrupted| **corrupted).count())
            .collect();
        assert_eq!(corrupted, [4, 2, 2, 2]);

        // this hurts a lot more windows than corrupting random validators
        let cheapest = evaluate_test_hubs(DecisionRule::Unanimous, Fault::Byzantine, strategy, 0.1);
        let random = evaluate_test_hubs(
            DecisionRule::Unanimous,
            Fault::Byzantine,
            AdversaryStrategy::Random,
            0.1,
        );
        assert!(cheapest.0.skip_rate() > random.0.skip_rate() + 0.1);
    }

    #[test]
    fn whole_hubs_adversary() {
        // 10% of the stake buys two of the small hubs, and thus all of their windows:
        // each small hub gets 0.5 * 5% + 0.5 / 4 = 15% of the windows
        for fault in FAULTS {
            let (stats, corrupted_stake) = evaluate_test_hubs(
                DecisionRule::Unanimous,
                fault,
                AdversaryStrategy::WholeHubs,
                0.1,
            );
            assert!((corrupted_stake - 0.1).abs() < EPSILON);
            assert!((stats.skip_rate() - 0.3).abs() < TOLERANCE);
            let capture_rate = match fault {
                Fault::Byzantine => 0.3,
                Fault::Crashed => 0.0,
            };
            assert!((stats.capture_rate() - capture_rate).abs() < TOLERANCE);
        }
    }

    #[test]
    fn own_hubs_adversary() {
        // 5% of the stake is enough for five hubs of 1% each, next to the four existing
        // hubs, and every hub gets a minimum share of 0.5 / 9 of the windows:
        // 5 * (0.5 * 1% + 0.5 / 9) = 30.3%
        let mut rng = StdRng::seed_from_u64(42);
        let hubs = test_hubs();
        let params = NewconParameters::PAPER;
        let corruption = AdversaryStrategy::OwnHubs.corrupt(&hubs, &params, 0.05, &mut rng);
        assert_eq!(corruption.hubs.len(), 9);
        let schedule = ProposerSchedule::new(&corruption.hubs, &params);
        let own_share: f64 = (4..9).map(|hub| schedule.window_share(hub)).sum();
        assert!((own_share - 0.3028).abs() < 1e-3);

        let (stats, corrupted_stake) = evaluate_test_hubs(
            DecisionRule::Unanimous,
            Fault::Byzantine,
            AdversaryStrategy::OwnHubs,
            0.05,
        );
        assert!((corrupted_stake - 0.05).abs() < EPSILON);
        assert!((stats.capture_rate() - own_share).abs() < TOLERANCE);

        // less than the minimum hub stake is not enough for a hub
        let corruption = AdversaryStrategy::OwnHubs.corrupt(&hubs, &params, 0.005, &mut rng);
        assert_eq!(corruption.hubs.len(), 4);
        assert_eq!(corruption.stake, 0.0);
    }
}
