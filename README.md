# Cronos402 MCP v2

x402 monetization wrapper for MCP servers. Enables non-monetized servers to create payment-gated links with different monetization strategies.

## Features

- Wrap existing MCP servers with x402 payments
- Multiple monetization strategies per server
- Upstash Redis for serverless state management

## Development

```bash
pnpm dev
```

## Build

```bash
pnpm build
```

## Migration

```bash
pnpm migrate:upstash  # Migrate data to Upstash
```
