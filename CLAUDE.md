# WebSecAuditor

> AST Taint Security Scanner & Automated GitHub PR Security Bot.

## Core Engines
- `src/ast/`: AST parser and source-to-sink taint propagation analyzer.
- `src/entropy/`: Shannon entropy scoring engine (H >= 4.5) for credential detection.
- `src/sarif/`: OASIS SARIF v2.1.0 generator for GitHub Code Scanning integration.
- `src/github/`: GitHub Action integration posting automated inline diff comments.

## Commands
- Run Tests: `pnpm test`
- Build CLI: `pnpm build`
- Self-Audit: `node dist/index.js scan ./src`
