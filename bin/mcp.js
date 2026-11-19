#!/usr/bin/env node
import { startMcpServer } from "../dist/mcp/index.js";

startMcpServer().catch((err) => {
  console.error("Fatal error starting WebSecAuditor MCP server:", err);
  process.exit(1);
});
