# Claim boundaries

XIR's [paper](https://arxiv.org/abs/2609.20010),
[observational dataset](https://www.kaggle.com/datasets/yushenlee/xir-cross-chain-events-2025),
and execution campaigns provide distinct evidence. Every execution result must
identify its environment, protocol sequence, implementation revision, verifier
configuration, workload, and sample denominator.

## Observed graph and provisioning model

The dataset contains 24,983,410 distinct `(protocol, event_id)` events from six
protocol feeds between January and October 2025. Identity resolution and
mainnet, distinct-network filtering produce a graph with 286 active networks.
The paper's 78,953 reachable ordered pairs (96.86%) describe composition over
that cumulative graph, assuming the XIR components and protocol configurations
needed along each path.

These values do not establish that all edges were live simultaneously, that
XIR was deployed on every observed blockchain, or that an unobserved connection
was unsupported. Temporal windows and edge-activity thresholds change the
reachable set. Feed counts also do not establish protocol market share or
complete ecosystem coverage.

The 67,018 additional reachable pairs equal 78,953 minus 11,935 direct pairs.
Under the paper's direct-connectivity model, reaching those additional pairs
directly requires 67,018 new point-to-point configurations. Gateway deployments,
protocol integrations, configuration actions, and deployment gas are distinct
units; a configuration is not assumed to require a new pair of contracts.

## Execution evidence

| Evidence class | Interpretation |
| --- | --- |
| Synthetic fixtures and controlled-carrier lab | Exercise planning, state transitions, reconciliation, recovery, and evidence handling; protocol labels alone do not establish native protocol execution |
| Native protocol-stack campaigns | Measure the deployed Hyperlane/LayerZero components on the recorded Besu QBFT chains, with the specified local verification roles |
| Multi-hop campaign | The paper reports 22,000 executions across eleven paths, with one to four protocol connections; the cost models apply to those observations |
| Public-testnet records | Establish the preserved outcomes for the named routes and deployments; the paper reports seven deliveries from eleven attempts |
| Adversarial conformance campaign | Exercise the implemented acceptance/rejection checks; 780 case-runs cover thirteen classes in two directions |

The earlier 10,000-attempt controlled-carrier profile and the 40,000-request
native four-route campaign have separate identities. The local LayerZero
worker performs research observation, signing, and execution roles; it is
not a managed LayerZero Labs DVN or Executor. Native local results do not
measure public Hyperlane or LayerZero capacity, public service latency, or
production reliability.

Experiment 2 and Experiment 3 reuse the HL observations. Their respective
6,000 and 16,000 analysis samples overlap; they are not disjoint components of
the 22,000-execution campaign. Stage-latency samples count stage instances,
which can exceed the number of complete executions.

The preserved public-testnet records have no eligible matched baseline pairs.
They support absolute observations for the recorded attempts. An
XIR-minus-baseline overhead requires matched routes, inputs, environments,
and eligible samples from both arms. Planning a paired experiment does not
establish that its measurements were collected.

## Trust, costs, and reporting

The paper's theorem is conditional on sound protocol deliveries, correct XIR
components and source certification, authentic configuration, and cryptographic
binding. It does not prove the correctness of all deployed protocol or XIR
implementations. Adversarial cases test the specified checks under their
recorded configuration; they do not establish production security.

Runner budgets describe experiment-controlled accounts. Externally funded
protocol activity must be labeled separately. Gas, calldata bytes, execution
fees, protocol payments, L1 data fees, and native asset amounts remain separate
measures unless a released method defines and supports a conversion.
Unavailable internal trace or service measurements cannot be interpreted as
zero cost.

Failures, timeouts, incomplete evidence, retries, and attempts not submitted
remain visible in their campaign's accounting. Reports must state whether a
result counts designated requests, successful executions, retries, stages, or
physical transactions. Retries do not silently replace designated attempts.

The implementation is a research prototype. Its recorded workloads do not
establish arbitrary-chain or arbitrary-hop support, production readiness,
mainnet safety, security equivalence across protocols, or real-currency costs
inferred from testnet assets.
