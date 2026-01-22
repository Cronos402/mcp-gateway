![Cronos402 Logo](https://raw.githubusercontent.com/Cronos402/assets/main/Cronos402-logo-light.svg)

# Cronos402 MCP Gateway

Payment enforcement proxy that wraps any existing MCP server with x402 payment requirements.

Production URL: https://gateway.cronos402.dev

## Overview

The MCP Gateway acts as a payment enforcement layer, allowing you to monetize any existing MCP server without modifying its code. It intercepts tool calls, validates payments using the x402 protocol, and forwards requests to the upstream MCP server only after successful payment verification. This enables developers to add payment requirements to both their own servers and third-party MCP services.

## Architecture

- **Framework**: Express.js with TypeScript
- **Payment Protocol**: x402 with Cronos facilitator
- **Proxy Pattern**: Transparent request/response forwarding
- **Blockchain**: Cronos testnet and mainnet support
- **Database**: Drizzle ORM for payment tracking
- **Transport**: HTTP streaming with backpressure handling

## Features

- Wrap any MCP server with payment requirements
- Transparent proxy - no upstream server modifications needed
- USDC.e gasless payments via Cronos facilitator
- Native CRO direct payment support
- Configurable per-tool pricing
- Automatic payment verification and settlement
- Request logging and analytics
- Error handling and retry logic
- Compatible with all MCP clients

## Quick Start

### Development

```bash
pnpm install
pnpm dev
```

Server runs on `http://localhost:3006`

### Build

```bash
pnpm build
pnpm start
```

### Environment Variables

```env
DATABASE_URL=postgresql://user:password@localhost:5432/cronos402
UPSTREAM_MCP_URL=https://upstream-server.com/mcp
CRONOS_NETWORK=cronos-testnet
RECIPIENT_ADDRESS=0xYourAddress
FACILITATOR_URL=https://facilitator.cronoslabs.org/v2/x402
```

## Configuration

### Tool Pricing

Configure per-tool pricing in your environment or database:

```typescript
const toolPricing = {
  'get_weather': '0.01',      // $0.01 per call
  'premium_data': '0.10',     // $0.10 per call
  'ai_analysis': '0.50'       // $0.50 per call
};
```

### Upstream Server

Point to any MCP server:

```env
UPSTREAM_MCP_URL=https://api.example.com/mcp
```

The gateway will proxy all MCP operations to this server after payment validation.

## How It Works

### Payment Flow

1. Client sends MCP tool call request to gateway
2. Gateway checks for payment in `_meta['x402/payment']`
3. If no payment:
   - Return 402 Payment Required
   - Include price, recipient, facilitator URL
4. If payment provided:
   - Verify payment signature and amount
   - Validate with Cronos facilitator
   - Forward request to upstream MCP server
   - Return upstream response to client
5. Facilitator settles payment on-chain

### Request Forwarding

```
Client → Gateway → Upstream MCP Server
         ↓
    Payment Check
         ↓
    Facilitator
```

## Usage Examples

### Wrap Existing Server

```typescript
import { createMcpGateway } from '@cronos402/mcp-gateway';

const gateway = createMcpGateway({
  upstreamUrl: 'https://api.example.com/mcp',
  recipient: '0xYourAddress',
  network: 'cronos-testnet',
  pricing: {
    'tool_name': '0.01'
  }
});

gateway.listen(3006);
```

### Client Integration

Clients use the gateway URL instead of the upstream server:

```bash
# Instead of connecting to upstream directly
npx cronos402 connect --urls https://api.example.com/mcp

# Connect through payment gateway
npx cronos402 connect --urls https://gateway.cronos402.dev/proxy/api.example.com
```

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "Paid Service": {
      "command": "npx",
      "args": [
        "cronos402",
        "connect",
        "--urls",
        "https://gateway.cronos402.dev/proxy/upstream",
        "--private-key",
        "0x...",
        "--network",
        "cronos-testnet"
      ]
    }
  }
}
```

## API Endpoints

### POST /mcp
Gateway MCP endpoint. Proxies to upstream after payment validation.

### GET /health
Health check endpoint.

### GET /pricing
Returns current tool pricing configuration.

### POST /admin/pricing
Update tool pricing (requires admin authentication).

## Database Schema

### Tables

- `gateway_requests` - All proxied requests
- `payment_validations` - Payment verification records
- `tool_usage` - Per-tool usage statistics
- `upstream_servers` - Registered upstream servers

### Migrations

```bash
pnpm drizzle-kit generate
pnpm drizzle-kit migrate
```

## Deployment

### Production Build

```bash
pnpm build
NODE_ENV=production pnpm start
```

### Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install --frozen-lockfile
COPY . .
RUN pnpm build
EXPOSE 3006
CMD ["pnpm", "start"]
```

### Environment Requirements

- PostgreSQL database for tracking
- HTTPS endpoint in production
- Valid Cronos recipient address
- Access to upstream MCP server
- Facilitator connectivity

## Testing

```bash
# Run all tests
pnpm test

# Watch mode
pnpm test:watch

# Coverage
pnpm test:coverage
```

## Monitoring

- `GET /health` - Server health status
- `GET /metrics` - Prometheus metrics
- Request logging to stdout
- Payment validation tracking

## Security

- Payment signatures verified on-chain
- Request validation before proxying
- Rate limiting per client
- Upstream timeout protection
- Input sanitization

## Troubleshooting

### Payment Verification Fails
- Ensure facilitator URL is correct
- Check recipient address matches requirements
- Verify payment amount is sufficient

### Upstream Timeout
- Increase timeout configuration
- Check upstream server health
- Review network connectivity

### Tool Not Found
- Verify upstream server exposes the tool
- Check tool name spelling
- Review proxy logs for errors

## Resources

- Documentation: https://docs.cronos402.dev/gateway
- SDK: https://github.com/Cronos402/sdk
- GitHub: https://github.com/Cronos402/mcp-gateway

## License

MIT
