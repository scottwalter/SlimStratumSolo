# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SlimStratumSolo is a NodeJS Stratum proxy for cryptocurrency mining (specifically DigiByte) that bridges BitaxeOS miners to DigiByte Core nodes for solo mining. It implements a simplified Stratum v1 protocol without dependencies on heavy frameworks like Express.

## Commands

- **Start server**: `npm start` or `node server.js`
- **Install dependencies**: `npm install`

## Architecture

### Core Components

- **server.js**: Main stratum proxy server handling miner connections and block template management
- **src/backend/controller/rpcServices.js**: RPC client for communicating with DigiByte Core node
- **src/backend/builder/blockTemplateBuilder.js**: Fetches block templates from the cryptocurrency node
- **src/backend/builder/submitBlockBuilder.js**: Constructs full block hex for submission (unused in current implementation)
- **src/backend/utils/verifyShares.js**: Validates mining shares and determines if they meet network/pool targets

### Key Configuration (server.js:11-27)

- `proxyPort`: Port for miners (default 3333)
- `rpcHost`/`rpcPort`: DigiByte Core node connection
- `rpcAuth`: Authentication for RPC calls
- `poolPayoutAddress`: Address for block rewards
- `defaultDifficulty`: Minimum mining difficulty

### Mining Flow

1. **Job Management**: Fetches block templates every 10 seconds via `fetchAndNotifyNewJob()`
2. **Miner Protocol**: Handles standard Stratum methods (subscribe, authorize, submit)
3. **Share Processing**: Validates submitted work using double SHA256 hashing
4. **Block Submission**: Submits valid blocks directly to DigiByte Core node

### Critical Implementation Details

- Uses raw TCP sockets (net module) instead of WebSocket or HTTP
- Implements custom little-endian hex conversion functions
- Handles SegWit witness commitments in coinbase transactions
- Block header construction follows Bitcoin/DigiByte 80-byte format
- Merkle root calculation for single coinbase transaction scenarios

### Known Issues

- Line 318: Variable name case mismatch (`Verify` vs `verify`)
- submitBlockBuilder.js has unused example code and undefined variable reference (line 159)

## Development Notes

- The proxy accepts all authorization attempts (line 235)
- Transaction verification uses simplified approach for solo mining
- No persistent storage - all state is in-memory
- Graceful shutdown handlers for SIGTERM/SIGINT