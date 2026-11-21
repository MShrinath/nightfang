# Methodology: blockchain

Source: [PentestingEverything/BlockChain Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/BlockChain%20Pentesting)

---

# Blockchain Pentesting Checklist

## Core Concepts

Blockchain pentesting assesses the security of distributed ledger systems and their surrounding components: smart contracts, nodes, consensus, wallets, key management, and the APIs and dApps that interact with them. The goal is to find flaws that let an attacker steal funds, manipulate state, disrupt consensus, or compromise keys, since on-chain actions are typically irreversible.

**Methodology**
- Scope and platform identification: determine the chain, consensus mechanism, and components in scope.
- Smart contract review: analyze contract logic for vulnerabilities and unsafe access control.
- Node and infrastructure assessment: review node configuration, RPC/API exposure, and key storage.
- Wallet and key management: test how private keys are generated, stored, and protected.
- Consensus and network analysis: evaluate the consensus algorithm and node behavior for abuse.
- Triage and report: confirm impact (funds, state, availability) and document remediation.

**What to look for**
- Smart contract bugs: reentrancy, integer overflow, unchecked external calls, and broken access control.
- Exposed or unauthenticated RPC/API endpoints and missing rate limiting.
- Private key exposure or weak key management and wallet storage.
- Insecure or upgradeable contracts that allow unintended state changes.
- Consensus weaknesses, replay issues, and data privacy gaps in stored or transmitted data.

## Network Assessment

- [ ] Identify the blockchain platform.
- [ ] Understand the consensus mechanism.
- [ ] Analyze the network topology.
- [ ] Verify the security model.
- [ ] Enumerate network ports and services.

## Smart Contract Assessment

- [ ] Review smart contract code for vulnerabilities.
  - **Tools:** [Mythril](https://github.com/ConsenSys/mythril), [Securify](https://github.com/eth-sri/securify), [Slither](https://github.com/crytic/slither)
  - **Commands:** Mythril command, Securify command, Slither command
- [ ] Verify contract access control mechanisms.
- [ ] Analyze contract state changes and transactions.
  - **Tools:** [Truffle](https://www.trufflesuite.com/truffle), [Ganache](https://www.trufflesuite.com/ganache)
- [ ] Assess contract upgradeability.

## Node Security

- [ ] Secure access to blockchain nodes.
- [ ] Review node configuration files.
- [ ] Monitor and protect private keys.
  - **Tools:** Hardware Security Modules (HSMs)
- [ ] Implement firewall rules for node security.

## Wallet and K

---

