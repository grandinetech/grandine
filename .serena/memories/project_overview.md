# Grandine Project Overview

## Project Purpose
Grandine is a fast and lightweight Ethereum consensus client written in Rust. It is designed for performance and memory efficiency, requiring only ~2.5GB of memory on mainnet. The project is production-ready and has undergone security audits.

## Key Features
- Optimized and parallelized consensus client implementation
- Can run 50,000 Holesky validators on a single machine
- Memory efficient (~2.5GB on mainnet)
- Production-ready with security audits completed

## Technology Stack
- **Language**: Rust (stable-2025-06-26)
- **Build System**: Cargo with workspace structure
- **Key Dependencies**:
  - BLS cryptography libraries (blst, zkcrypto)
  - Ethereum types and utilities
  - libp2p for networking
  - Tokio for async runtime
  - Axum for HTTP APIs
  - Various consensus and execution layer implementations

## Security Agent Component
The repository includes a security-agent written in Python that performs:
- Static code analysis for Solidity and JavaScript
- AI-powered vulnerability assessment using GPT-4o
- Call graph generation and visualization
- Multi-phase security analysis workflow
- Bug bounty research automation

## Repository Type
This is the main Grandine consensus client repository with an integrated security analysis tool suite.