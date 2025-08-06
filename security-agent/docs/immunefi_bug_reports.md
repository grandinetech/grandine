# ImmuneFi Bounty Reports

## Overview

This document analyzes historical bounty reports collected from the ImmuneFi report site (<https://reports.immunefi.com/>) and systematically summarizes security-vulnerability categories and attack vectors.

Target projects examined:

- Alchemix
- BadgerDAO (eBTC)
- DeGate
- Folks Finance
- IDEX
- ZeroLend
- Puffer Finance

## Report Categories (by Severity)

### Critical
- Unauthorized minting
- Infinite minting
- Insolvency in `RevenueHandler`
- Duplicate-handling error in binary search
- Permanent freeze of reward tokens
- Insufficient slippage control
- Slash during withdrawal
- Attacker takeover of protocol control

### High
- Permanent freeze of unclaimed assets
- Loss of queued data
- Boolean-check errors
- Token-deposit issues

### Medium
- Denial-of-service (DoS) attacks
- Front-running attacks
- User fund loss
- Unauthorized NFT minting
- Lock-end validation issues
- Voting-lock manipulation

### Low
- Precision loss
- Revival of previously-defeated proposals
- ERC-compliance violations
- Access-control flaws
- Use of deprecated APIs
- Rounding errors
- Batch-redemption issues
- Timelock-transaction issues
- Interface-support issues
- Time-weighted-average implementation issues

### Insight
- Invalid checks
- Reentrancy
- Flash-loan abuse
- Lido slashing
- Fund freezing
- Timelock exploitation
- Proxy-ownership transfer
- Malicious multisig implementation
- Faulty upgrade functions
- Floating pragma usage
- Stale price validation
- Exit-quote quantity validation
- Unfair liquidation
- Withdrawal delegation call
- Reward loss
- EigenLayer share-rate inflation
- Gas griefing
- Missing restricted modifiers
- Improper validation
- User blocking attacks

## Attack-Vector Classification

### Mint-Related Attacks
- Unauthorized minting
- Infinite minting
- Unauthorized NFT minting

### Fund & Token Attacks
- User fund loss
- Fund freezing
- Token freezing
- Permanent freeze of reward tokens
- Permanent freeze of unclaimed assets
- Reward loss

### Trade & Price-Manipulation Attacks
- Front-running
- Precision loss
- Slippage-control issues
- Stale price validation
- EigenLayer share-rate inflation

### Denial-of-Service Attacks
- DoS attacks
- DoS force-withdraw attacks
- User‐blocking attacks
- Gas griefing

### Reentrancy & Flash-Loan Attacks
- Reentrancy
- Flash-loan exploitation

### Access-Control / Permission Attacks
- Access-control flaws
- Attacker takeover of control
- Proxy-ownership transfer
- Malicious multisig implementation
- Missing restricted modifiers

### Timelock / Lock-Related Attacks
- Timelock exploitation
- Timelock-delay issues
- Voting-lock manipulation
- Lock-end validation issues

### Liquidation & Withdrawal Attacks
- Unfair liquidation
- Slash during withdrawal
- Withdrawal delegation call

### Implementation & Validation Attacks
- Binary-search vulnerability
- `upgradeToAndCall` flaw
- Boolean-check errors
- Improper validation
- Exit-quote quantity validation

### API / Interface Attacks
- Use of deprecated APIs
- Interface-support issues
- Floating pragma usage

### Data-Handling Attacks
- Queued data loss
- Rounding issues
- Time-weighted-average implementation issues
- Batch-redemption issues

### External-Dependency Attacks
- Lido slashing
- Token-deposit issues
