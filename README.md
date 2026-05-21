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