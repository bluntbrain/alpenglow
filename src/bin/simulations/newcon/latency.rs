// Copyright (c) Anza Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Latency simulation for NewCon, the MCP protocol.
//!
//! Simulates a single slot on the happy path. The `k` proposers of the slot
//! are drawn from one hub, according to the proposer schedule. Then:
//! - Every proposer disseminates its (encrypted) block via Rotor.
//! - Together with the last slice, every proposer sends a commitment to its
//!   block directly to its co-proposers.
//! - Once a proposer holds the commitments of all co-proposers, it sends its
//!   attestation, which contains the key of its block, directly to all validators.
//! - A validator can decrypt, merge and execute the slot once it holds the
//!   blocks and the attestations of all proposers.
//!
//! The simulation starts when the proposers have their last slice ready. It
//! ignores that co-proposers may start up to `∆local` apart, and that validators
//! only vote once per consensus block, i.e. every few slots.
//!
//! The paper claims that NewCon adds no extra latency, since the attestations
//! take a direct path while the blocks take the extra relay hop of Rotor.
//! To check this, the simulation also tracks the block of a single proposer,
//! which is what a validator would wait for with a single leader in the same place.
//!
//! So far, this test can only simulate the happy path.

use std::marker::PhantomData;
use std::path::PathBuf;

use alpenglow::disseminator::rotor::{
    QuorumSamplingStrategy, SamplingStrategy, StakeWeightedSampler,
};
use alpenglow::network::simulated::ping_data::PingServer;
use alpenglow::{ValidatorIndex, ValidatorInfo};
use anyhow::Result;
use log::info;
use rand::prelude::*;

use super::coverage::hubs_from_validators;
use super::hubs::Hub;
use super::parameters::NewconParameters;
use super::schedule::ProposerSchedule;
use crate::discrete_event_simulator::{
    Builder, Event, Protocol, Resources, SimTime, SimulationEngine, SimulationEnvironment, Stage,
    Timings, column_max,
};
use crate::rotor::{RotorInstance, RotorInstanceBuilder, RotorLatencySimulation, RotorParams};

/// Number of slots to simulate.
const NUM_ITERATIONS: u64 = 1000;
/// Size (in bytes) assumed per commitment in the simulation.
const COMMITMENT_SIZE: usize = 64 /* sig */ + 32 /* hash */ + 32 /* slot, proposer */;
/// Size (in bytes) assumed per attestation in the simulation.
const ATTESTATION_SIZE: usize = 64 /* sig */ + 32 /* key */ + 256 /* hashes, slot, proposer */;

/// Runs the NewCon latency simulation, with the parameters suggested in the paper.
///
/// The `validators` have to be the ones that the `environment` was created from,
/// and that `rotor_sampler` samples from.
///
/// Writes the latency percentiles to `data/output/simulations/newcon/`.
pub(crate) fn run_latency_simulation<R: QuorumSamplingStrategy + Clone + Send + Sync>(
    validators: &[(ValidatorInfo, &'static PingServer)],
    environment: &SimulationEnvironment,
    rotor_sampler: &R,
) -> Result<()> {
    let newcon_params = NewconParameters::PAPER;
    let hubs = hubs_from_validators(validators, newcon_params.delta_local_ms);
    // a proposer block of a 50 ms slot is small, so a single slice is enough
    let shreds = rotor_sampler.quorum_size();
    let rotor_params = RotorParams::new(shreds / 2, shreds, 1);
    let builder =
        NewconInstanceBuilder::new(&hubs, &newcon_params, rotor_sampler.clone(), rotor_params);
    let params = *builder.params();
    let engine = SimulationEngine::<NewconLatencySimulation<R>>::new(builder, environment.clone());
    info!("newcon latency sim (parallel)");
    engine.run_many_parallel(NUM_ITERATIONS);

    for event in [
        LatencyEvent::Block(0),
        LatencyEvent::Blocks,
        LatencyEvent::Attestations,
        LatencyEvent::Slot,
    ] {
        let percentile = |percentile: u8| {
            engine
                .stats()
                .get(&event)
                .expect("event stats should exist for tracked event")
                .get_avg_percentile_latency(percentile)
        };
        info!(
            "newcon latency ({shreds} shreds) until {}: median {:.1} ms, 90th percentile {:.1} ms",
            event.name(),
            percentile(50),
            percentile(90),
        );
    }

    let csv_path = PathBuf::from("data")
        .join("output")
        .join("simulations")
        .join("newcon")
        .join(format!("latency-{}-{shreds}.csv", shreds / 2));
    if let Some(parent) = csv_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    engine.stats().write_to_csv(csv_path, &params)?;

    Ok(())
}

/// Wrapper type for the NewCon latency simulation.
///
/// This type implements the `Protocol` trait and can be passed to the simulation engine.
/// There is probably never a need to construct this type directly.
pub(crate) struct NewconLatencySimulation<R: QuorumSamplingStrategy> {
    _rotor_sampler: PhantomData<R>,
}

impl<R: QuorumSamplingStrategy> Protocol for NewconLatencySimulation<R> {
    type Event = LatencyEvent;
    type Stage = LatencyTestStage;
    type Params = NewconLatencyParams;
    type Instance = NewconInstance;
    type Builder = NewconInstanceBuilder<R>;
}

/// Stages of the NewCon latency simulation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum LatencyTestStage {
    Proposers,
    Collect,
    Slot,
}

impl Stage for LatencyTestStage {
    type Event = LatencyEvent;
    type Params = NewconLatencyParams;

    fn first() -> Self {
        Self::Proposers
    }

    fn next(&self) -> Option<Self> {
        match self {
            Self::Proposers => Some(Self::Collect),
            Self::Collect => Some(Self::Slot),
            Self::Slot => None,
        }
    }

    fn events(&self, params: &Self::Params) -> Vec<LatencyEvent> {
        match self {
            Self::Proposers => {
                let proposers = 0..params.num_proposers;
                let blocks = proposers.clone().map(LatencyEvent::Block);
                let attestations = proposers.map(LatencyEvent::Attestation);
                blocks.chain(attestations).collect()
            }
            Self::Collect => vec![LatencyEvent::Blocks, LatencyEvent::Attestations],
            Self::Slot => vec![LatencyEvent::Slot],
        }
    }
}

/// Events that can occur at each validator during the NewCon latency simulation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum LatencyEvent {
    /// The validator reconstructed the block of the proposer with the given index.
    Block(usize),
    /// The validator received the attestation of the proposer with the given index.
    Attestation(usize),
    /// The validator reconstructed the blocks of all proposers.
    Blocks,
    /// The validator received the attestations of all proposers.
    Attestations,
    /// The validator holds everything it needs to decrypt, merge and execute the slot.
    Slot,
}

impl Event for LatencyEvent {
    type Params = NewconLatencyParams;
    type Instance = NewconInstance;

    fn name(&self) -> String {
        match self {
            Self::Block(proposer) => format!("block_{proposer}"),
            Self::Attestation(proposer) => format!("attestation_{proposer}"),
            Self::Blocks => "blocks".to_owned(),
            Self::Attestations => "attestations".to_owned(),
            Self::Slot => "slot".to_owned(),
        }
    }

    fn should_track_stats(&self) -> bool {
        match self {
            // the block of one proposer is the baseline, same as with a single leader
            Self::Block(proposer) => *proposer == 0,
            Self::Attestation(_) => false,
            Self::Blocks | Self::Attestations | Self::Slot => true,
        }
    }

    fn dependencies(&self, params: &NewconLatencyParams) -> Vec<Self> {
        match self {
            Self::Block(_) | Self::Attestation(_) => vec![],
            Self::Blocks => (0..params.num_proposers).map(Self::Block).collect(),
            Self::Attestations => (0..params.num_proposers).map(Self::Attestation).collect(),
            Self::Slot => vec![Self::Blocks, Self::Attestations],
        }
    }

    fn calculate_timing(
        &self,
        start_time: SimTime,
        dependency_timings: &[&[SimTime]],
        instance: &NewconInstance,
        _resources: &mut Resources,
        environment: &SimulationEnvironment,
    ) -> Vec<SimTime> {
        match self {
            Self::Block(proposer) => {
                // TODO: find better way of integrating sub-protocol
                let rotor_params = instance.params.rotor_params;
                let builder = RotorInstanceBuilder::new(
                    StakeWeightedSampler::new(environment.validators.clone())
                        .into_quorum_strategy(1),
                    StakeWeightedSampler::new(environment.validators.clone())
                        .into_quorum_strategy(rotor_params.shreds),
                    rotor_params,
                );
                let engine = SimulationEngine::<RotorLatencySimulation<_, _>>::new(
                    builder,
                    environment.clone(),
                );
                let mut timings = Timings::new(start_time);
                engine.run(&instance.rotor_instances[*proposer], &mut timings);
                timings
                    .get(crate::rotor::LatencyEvent::Block)
                    .expect("rotor block event should be recorded")
                    .to_vec()
            }
            Self::Attestation(proposer) => {
                let proposer = instance.proposers[*proposer];
                // the proposer attests once it holds the commitments of all co-proposers
                let commitments_time = instance
                    .proposers
                    .iter()
                    .filter(|co_proposer| **co_proposer != proposer)
                    .map(|co_proposer| {
                        start_time
                            + environment.propagation_delay(*co_proposer, proposer)
                            + environment.transmission_delay(COMMITMENT_SIZE, *co_proposer)
                    })
                    .max()
                    .unwrap_or(start_time);
                (0..environment.num_validators())
                    .map(|recipient| {
                        let prop_delay = environment
                            .propagation_delay(proposer, ValidatorIndex::new(recipient as u64));
                        let tx_delay = environment
                            .transmission_delay((recipient + 1) * ATTESTATION_SIZE, proposer);
                        commitments_time + prop_delay + tx_delay
                    })
                    .collect()
            }
            Self::Blocks | Self::Attestations | Self::Slot => column_max(dependency_timings),
        }
    }
}

/// Parameters for the NewCon latency simulation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NewconLatencyParams {
    /// Number of concurrent proposers.
    num_proposers: usize,
    /// Parameters for the dissemination of every proposer block via Rotor.
    rotor_params: RotorParams,
}

/// Specific instance of the NewCon latency simulation.
pub(crate) struct NewconInstance {
    /// The co-located proposers of the slot.
    proposers: Vec<ValidatorIndex>,
    /// One Rotor instance per proposer, for the dissemination of its block.
    rotor_instances: Vec<RotorInstance>,
    params: NewconLatencyParams,
}

/// Builder for NewCon latency simulation instances.
pub(crate) struct NewconInstanceBuilder<R: QuorumSamplingStrategy> {
    schedule: ProposerSchedule,
    /// The members of every hub, as referred to by the windows of the schedule.
    hub_validators: Vec<Vec<ValidatorIndex>>,
    rotor_sampler: R,
    params: NewconLatencyParams,
}

impl<R: QuorumSamplingStrategy> NewconInstanceBuilder<R> {
    /// Creates a new builder instance.
    ///
    /// The proposers are drawn from the active hubs among `hubs`, and the relays
    /// of Rotor are sampled from `rotor_sampler`. Both need to refer to the
    /// validators of the environment the simulation is run in.
    pub(crate) fn new(
        hubs: &[Hub],
        newcon_params: &NewconParameters,
        rotor_sampler: R,
        rotor_params: RotorParams,
    ) -> Self {
        assert_eq!(rotor_sampler.quorum_size(), rotor_params.shreds);
        Self {
            schedule: ProposerSchedule::new(hubs, newcon_params),
            hub_validators: hubs.iter().map(|hub| hub.validators().to_vec()).collect(),
            rotor_sampler,
            params: NewconLatencyParams {
                num_proposers: newcon_params.num_proposers,
                rotor_params,
            },
        }
    }
}

impl<R: QuorumSamplingStrategy> Builder for NewconInstanceBuilder<R> {
    type Params = NewconLatencyParams;
    type Instance = NewconInstance;

    fn build(&self, rng: &mut impl Rng) -> NewconInstance {
        let window = self.schedule.sample_window(rng);
        let proposers: Vec<ValidatorIndex> = window
            .proposers
            .iter()
            .map(|member| self.hub_validators[window.hub][*member])
            .collect();
        let rotor_params = self.params.rotor_params;
        let rotor_instances = proposers
            .iter()
            .map(|proposer| RotorInstance {
                leader: *proposer,
                relays: (0..rotor_params.slices)
                    .map(|_| self.rotor_sampler.sample_quorum(rng))
                    .collect(),
                params: rotor_params,
            })
            .collect();
        NewconInstance {
            proposers,
            rotor_instances,
            params: self.params,
        }
    }

    fn params(&self) -> &Self::Params {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Reverse;

    use alpenglow::disseminator::rotor::sampling_strategy::IidQuorumSampler;
    use alpenglow::network::simulated::stake_distribution::{
        VALIDATOR_DATA, validators_from_validator_data,
    };

    use super::*;

    const NUM_TEST_ITERATIONS: usize = 20;

    type RotorSampler = IidQuorumSampler<StakeWeightedSampler>;

    fn setup() -> (NewconInstanceBuilder<RotorSampler>, SimulationEnvironment) {
        let (_, mut validators) = validators_from_validator_data(&VALIDATOR_DATA);
        // use the same order and IDs as the simulation environment
        validators.sort_by_key(|(v, _)| Reverse(v.stake));
        for (i, (v, _)) in validators.iter_mut().enumerate() {
            v.id = ValidatorIndex::new(i as u64);
        }
        let environment = SimulationEnvironment::from_validators_with_ping_data(&validators);

        let newcon_params = NewconParameters::PAPER;
        let hubs = hubs_from_validators(&validators, newcon_params.delta_local_ms);
        let rotor_params = RotorParams::new(32, 64, 1);
        let rotor_sampler = StakeWeightedSampler::new(environment.validators.clone())
            .into_quorum_strategy(rotor_params.shreds);
        let builder =
            NewconInstanceBuilder::new(&hubs, &newcon_params, rotor_sampler, rotor_params);
        (builder, environment)
    }

    #[test]
    fn proposers_are_co_located() {
        let (builder, environment) = setup();
        let params = NewconParameters::PAPER;
        let max_delay = SimTime::from_secs(params.delta_local_ms / 1e3);
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..NUM_TEST_ITERATIONS {
            let instance = builder.build(&mut rng);
            assert_eq!(instance.proposers.len(), params.num_proposers);
            assert_eq!(instance.rotor_instances.len(), params.num_proposers);
            for (i, a) in instance.proposers.iter().enumerate() {
                assert_eq!(&instance.rotor_instances[i].leader, a);
                for b in &instance.proposers[..i] {
                    assert_ne!(a, b);
                    let d = environment.propagation_delay(*a, *b);
                    let d2 = environment.propagation_delay(*b, *a);
                    assert!(d <= max_delay, "DEBUG a={a:?} b={b:?} d={d:?} d2={d2:?}");
                }
            }
        }
    }

    #[test]
    fn slot_needs_blocks_and_attestations() {
        let (builder, environment) = setup();
        let mut rng = StdRng::seed_from_u64(42);
        let instances: Vec<NewconInstance> = (0..NUM_TEST_ITERATIONS)
            .map(|_| builder.build(&mut rng))
            .collect();
        let engine =
            SimulationEngine::<NewconLatencySimulation<RotorSampler>>::new(builder, environment);
        for instance in &instances {
            let mut timings = Timings::default();
            engine.run(instance, &mut timings);

            let block = timings.get(LatencyEvent::Block(0)).unwrap();
            let blocks = timings.get(LatencyEvent::Blocks).unwrap();
            let attestations = timings.get(LatencyEvent::Attestations).unwrap();
            let slot = timings.get(LatencyEvent::Slot).unwrap();
            for validator in 0..slot.len() {
                // waiting for all blocks takes at least as long as waiting for one
                assert!(blocks[validator] >= block[validator]);
                // the slot is ready exactly when the last block or attestation arrives
                let last = blocks[validator].max(attestations[validator]);
                assert_eq!(slot[validator], last);
                assert!(slot[validator] < SimTime::NEVER);
            }
        }
    }
}
