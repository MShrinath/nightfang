# Blockchain Security Assessment Workflow

## Scope

This workflow assesses security posture of blockchain-based systems including smart contracts (EVM-compatible, Solana, Cosmos), decentralized applications (dApps), token standards (ERC-20, ERC-721, SPL), DeFi protocols, and related infrastructure (node operators, wallet services, bridge contracts). Focus areas include contract-level vulnerabilities, consensus mechanism assumptions, economic exploit vectors, and custody architecture weaknesses. No on-chain transactions involving real value are executed during assessment.

## Prerequisites

- Target addresses, contract ABI/interface specifications, and RPC endpoint URLs provided within scope authorization.
- Testnet or forked mainnet environment configured for safe transaction simulation without affecting live asset balances.
- Understanding of the target chain's consensus model, gas pricing mechanics, and upgradeability patterns (proxy contracts, metamorphic contracts).
- Operator confirmation that static analysis and off-chain simulation tools are approved for use within engagement boundaries.

**Skill Reference**: `AGENTS.md` § Advisory Mode, `manifest.yaml` capability definitions for blockchain-assessment

## Phase 1 — Contract Architecture & Dependency Mapping

Document the complete smart contract system including inheritance hierarchies and external dependencies.

1. Retrieve complete contract bytecodes and source maps from block explorers (Etherscan, SnowTrace, BscScan) or compile from verified source repositories.
2. Map contract inheritance chains identifying parent contracts, library links, upgradeable proxy patterns (UUPS, transparent, beacon), and implementation address references.
3. Catalog all external call targets: delegated calls to unverified contracts, oracle price feed dependencies, cross-chain bridge interfaces, and permissioned admin roles.
4. Document token economics: total supply, mint/burn capabilities, pause/unpause functions, ownership controls, and fee distribution mechanisms.
5. Identify deployed versions across multiple chains (mainnet, testnets, sidechains) and assess consistency of bytecode implementations between deployments.

**Tools**: Sourcify verification status check, Remix IDE project import, Foundry cast/anvil commands (read-only), Tenderly contract debugger, DeFiLlama protocol directory cross-reference.

**Skill Reference**: `skills/crypto`, `schemas/finding.md`

## Phase 2 — Static Vulnerability Analysis

Run formal static analysis tooling against contract source code to detect common vulnerability classes.

1. Execute Slither static analyzer targeting reentrancy vulnerability detection, integer overflow/underflow paths, uninitialized storage pointer usage, unchecked external call return values, and access control modifier gaps.
2. Run Mythril or MadMax for symbolic execution-based analysis of control flow exploitable paths, particularly around token transfer functions and liquidity pool interaction logic.
3. Apply MythX or OpenZeppelin Defender scan API (testnet configuration) for extended vulnerability classification covering flash loan attack surfaces, oracle manipulation vectors, and governance attack pathways.
4. Audit Solidity language feature usage for deprecated patterns (`tx.origin` authentication, block.timestamp dependency for randomness, assembly block misuse) identified in compiler warning outputs.
5. Verify adherence to ERC standard implementations by comparing function signatures, event emissions, and state variable access patterns against published standard specifications.

**HITL Gate Required Before**: Executing any transaction against live contract addresses, interacting with contracts holding significant locked value, or invoking functions that modify contract state even in simulated environments.

**Tools**: Slither, Mythril, Echidna (fuzzing harness setup, offline execution), MythX API, OpenZeppelin wizard compatibility checks.

**Skill Reference**: `skills/reverse-engineering`, `skills/api/scripts/graphql_audit.py`

## Phase 3 — Economic & Game-Theoretic Attack Surface

Analyze incentive structures and economic exploits possible within the protocol design.

1. Evaluate flash loan exploit feasibility by tracing cross-function call sequences that can borrow large capital amounts within a single transaction block to manipulate price or collateral valuations.
2. Assess governance attack vectors: token concentration ratios, voting delay periods, quorum thresholds, timelock durations, and proposals for privileged function upgrades accessible to minority token holders.
3. Identify oracle manipulation susceptibility by analyzing price feed aggregation methodology, decimal precision handling, stale quote rejection intervals, and single-source versus multi-source oracle dependence.
4. Review fee accumulation and distribution logic for MEV (miner extractable value) exploitation opportunities including sandwich attack exposure, liquidation bonus arbitrage, and frontrunning vulnerability in transaction ordering.
5. Model worst-case fund loss scenarios under concurrent attack conditions combining multiple identified vulnerabilities operating in coordinated sequence.

**Tools**: Formal verification aids (Certora Prover trial mode for critical paths), Foundry invariant testing framework, custom economic scenario modeling spreadsheets.

**Skill Reference**: `skills/crypto/scripts/cryptographic_analyzer.py`, `schemas/finding.md`

## Phase 4 — Wallet & Custody Architecture Review

Assess key management infrastructure controlling protocol treasury and administrative functions.

1. Map multisignature wallet configurations: signer count, threshold requirements, geographic distribution of signers, hardware wallet integration status, and emergency freeze capabilities.
2. Review transaction signing workflows for social engineering exposure points: signers communicating via unencrypted channels, offline signing procedure documentation gaps, phishing-resistant hardware device compliance verification.
3. Audit timelock and circuit breaker mechanisms protecting high-value administrative functions including contract pausing, parameter modification, and Treasury withdrawal authorization.
4. Assess operational security of developer accounts managing upgradeable proxy implementations: personal wallet separation, GPG-signed commit verification, multi-party computation adoption status.
5. Evaluate historical incident response patterns for similar DeFi protocol compromises to identify lessons-applicable safeguards missing from current implementation.

**Skill Reference**: `skills/reporting`, `skills/remediation`, `workflows/cloud-assessment.md` (custody parallels)
