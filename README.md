# Web3-Guard Sentinel

Web3-Guard Sentinel is an enterprise-grade static application security testing (SAST) utility and software composition analysis (SCA) engine designed for blockchain ecosystems. It evaluates project manifest dependencies against live vulnerability feeds and performs pattern-based static analysis on Solidity smart contracts to enforce automated security compliance within DevSecOps pipelines.

---

## System Architecture & Data Flow

The engine operates on a decoupled, modular design to maximize execution speed and maintain strict separation of concerns.

```mermaid
graph TD
    A[CLI Input / CI Pipeline] --> B(Sentinel Core Orchestrator)
    B --> C{Asset Discovery Engine}
    C -->|package.json| D[SCA Dependency Audit Module]
    C -->|*.sol| E[Solidity Static Analysis Module]
    
    D --> F[Local Threat Registry Fallback]
    D --> G[Google Upstream OSV API Feed]
    
    E --> H[AST-Heuristic Line Tokenizer]
    
    F --> I[Unified Report Aggregator]
    G --> I
    H --> I
    
    I --> J[JSON Structural Export]
    I --> K[Markdown Compliance Log]
    
    I --> L{Policy Enforcement Engine}
    L -->|Breach Detected| M[Process Exit 1 / Break Build]
    L -->|Compliant| N[Process Exit 0 / Pass Build]
```

## Module Breakdown

1. Orchestrator Context (sentinel.ts): Initializes core services, leverages native cross-platform token parsing to sanitize inputs, and configures enforcement thresholds.

2. SCA Engine (scanner.ts): Extracts the localized dependency tree and runs concurrent asynchronous lookups using a pool pattern.

3. Upstream Broker (osvService.ts): A network connection client interfacing with Google's Open Source Vulnerability (OSV) API database.

4. Solidity Parser (contractScanner.ts): Reads smart contract code sequentially to intercept known offensive vulnerability anti-patterns.

5. Automation Compliance Reporter (fileReporter.ts): Collects findings and handles asynchronous file system outputs.


## Core Features

* Real-Time Threat Intelligence: Queries live distributed CVE and GitHub Advisory (GHA) record networks concurrently.

* Smart Contract Static Analysis: Tokenizes raw .sol files to flags structural exploits, security bugs, and design anti-patterns.

* Pipeline Enforcement (Policy-as-Code): Supports strict severity thresholds (--fail-on HIGH) to break automated CI/CD builds when severe risks are introduced.

* Zero-Dependency Runtime Mapping: Runs natively using pure modern ECMAScript Modules (ESM) and Node.js core APIs for security and efficiency.