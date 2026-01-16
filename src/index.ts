import { Hono } from "hono";
import { cors } from "hono/cors";
import { AuthHeadersHook, LoggingHook, AnalyticsHook, withProxy, X402MonetizationHook, CRONOS_NETWORK, SUPPORTED_CRONOS_NETWORKS, CronosAssets, isCronosNetwork } from "cronos402";
import type { Price, CronosNetwork } from "cronos402";
import { redisStore, type StoredServerConfig } from "./db/redis.js";

// Network type for Cronos (replaces x402 Network type)
type Network = CronosNetwork | string;
import { config } from 'dotenv';
import getPort from "get-port";
import { serve } from "@hono/node-server";

config();

export const runtime = 'nodejs';

type RecipientWithTestnet = { address: string; isTestnet?: boolean };

// Initialize Redis store
async function initializeStore(): Promise<void> {
    try {
        await redisStore.connect();
        // No console logging
    } catch (error) {
        // No console logging
        throw error;
    }
}

// Resolve upstream target MCP origin from header/query (base64) or store by server id
async function resolveTargetUrl(req: Request, absoluteUrl?: string): Promise<string | null> {
    // No console logging
    // Use absoluteUrl if provided (from Hono context), otherwise try to construct from req.url
    let url: URL;
    try {
        if (absoluteUrl) {
            url = new URL(absoluteUrl);
        } else {
            // If req.url is relative, we need to construct an absolute URL
            // Try to use req.url directly first
            try {
                url = new URL(req.url);
            } catch {
                // If that fails, try constructing from headers
                const host = req.headers.get("host") || req.headers.get("x-forwarded-host");
                const protocol = req.headers.get("x-forwarded-proto") || "https";
                if (host) {
                    url = new URL(req.url, `${protocol}://${host}`);
                } else {
                    // Fallback: try req.url as-is (might work in some contexts)
                    url = new URL(req.url, "http://localhost");
                }
            }
        }
    } catch (e) {
        // If URL construction fails, return null
        return null;
    }
    
    const id = url.searchParams.get("id");
    // No console logging
    if (id) {
        const server = await redisStore.getServerById(id);
        // No console logging
        if (server?.mcpOrigin) {
            // No console logging
            return server.mcpOrigin;
        }
    }

    const directEncoded = req.headers.get("x-cronos402-target-url") ?? url.searchParams.get("target-url");
    if (directEncoded) {
        try {
            const decoded = atob(decodeURIComponent(directEncoded));
            return decoded;
        } catch {
            // if not base64, assume raw URL
            return directEncoded;
        }
    }
    return null;
}

async function buildMonetizationForTarget(targetUrl: string): Promise<{
    prices: Record<string, Price>;
    recipient: Partial<Record<Network, string>>;
} | null> {
    try {
        console.log('[buildMonetization] Looking up server for targetUrl:', targetUrl);
        const server = await redisStore.getServerByOrigin(targetUrl);
        console.log('[buildMonetization] Server found:', server ? 'yes' : 'no');
        if (!server) return null;
        console.log('[buildMonetization] Server recipient:', JSON.stringify(server.recipient));
        console.log('[buildMonetization] Server metadata.networks:', server.metadata?.networks);

        const tools = server.tools ?? [];
        console.log('[buildMonetization] Server tools:', tools.length);

        // Build recipients from the new recipient structure
        const recipient: Partial<Record<Network, string>> = {};

        // Get selected networks from metadata
        const selectedNetworks = server.metadata?.networks as string[] | undefined;
        
        // Only Cronos networks are supported - use centralized constants
        const supportedNetworks = [CRONOS_NETWORK.CRONOS, CRONOS_NETWORK.TESTNET];

        // Handle the new recipient format: { evm: { address: string, isTestnet?: boolean } }
        if (server.recipient?.evm?.address) {
            if (selectedNetworks && selectedNetworks.length > 0) {
                // Use only supported Cronos networks selected by the user
                const selectedCronosNetworks = selectedNetworks.filter(n =>
                    (supportedNetworks as readonly string[]).includes(n)
                );
                for (const network of selectedCronosNetworks) {
                    recipient[network as Network] = server.recipient.evm.address;
                }
            } else {
                // Fallback: Map EVM address to Cronos networks based on testnet flag
                const isTestnet = server.recipient.evm.isTestnet;
                const targetNetworks = isTestnet ? [CRONOS_NETWORK.TESTNET] : [CRONOS_NETWORK.CRONOS];
                for (const network of targetNetworks) {
                    recipient[network as Network] = server.recipient.evm.address;
                }
            }
        }

        // Note: SVM (Solana) is not supported in Cronos402 - only EVM (Cronos) networks

        // Fallback to old receiverAddressByNetwork if it exists (for backwards compatibility)
        if (!Object.keys(recipient).length && server.receiverAddressByNetwork) {
            const map = server.receiverAddressByNetwork ?? {};
            for (const [net, addr] of Object.entries(map)) {
                if (addr) recipient[net as Network] = String(addr);
            }
        }

        // If there are no recipients configured, monetization cannot be applied
        if (!Object.keys(recipient).length) return null;

        // Build prices per tool - convert string prices like "$0.01" to proper Price objects
        const prices: Record<string, Price> = {};
        for (const t of tools) {
            const pricing = t.pricing;
            if (typeof pricing === 'string' && pricing.startsWith('$')) {
                // Extract numeric value from string like "$0.01"
                const numericValue = parseFloat(pricing.substring(1));
                if (!isNaN(numericValue) && numericValue > 0) {
                    // Use the numeric value as Money type (which is string | number)
                    prices[t.name as string] = numericValue;
                }
            }
        }

        return { prices, recipient };
    } catch {
        return null;
    }
}

// Initialize Redis store at startup
void initializeStore();

const app = new Hono();
app.use("*", cors({
    origin: ['http://localhost:3000', 'http://localhost:3002', 'http://localhost:3005'],
    credentials: true,
}));

// Admin: register or update an MCP server config
app.post("/register", async (c) => {
    const body = await c.req.json().catch(() => null) as { 
        id?: string; 
        mcpOrigin?: string; 
        requireAuth?: boolean; 
        authHeaders?: Record<string, string>; 
        receiverAddressByNetwork?: Record<string, string>; 
        recipient?: { 
            evm?: { address: string; isTestnet?: boolean }; 
            svm?: { address: string; isTestnet?: boolean } 
        }; 
        tools?: Array<{ name: string; pricing: string }>; 
        metadata?: Record<string, unknown> 
    };
    if (!body || typeof body !== 'object') {
        return c.json({ error: "invalid_json" }, 400);
    }

    // Log registration request for debugging
    console.log('[Register] Received:', {
        id: body.id,
        mcpOrigin: body.mcpOrigin,
        recipient: body.recipient,
        networks: body.metadata?.networks,
    });

    const { id, mcpOrigin } = body;
    if (!id || !mcpOrigin) {
        return c.json({ error: "missing_id_or_origin" }, 400);
    }

    const input: Partial<StoredServerConfig> = {
        id,
        mcpOrigin,
        requireAuth: body.requireAuth === true,
        authHeaders: body.authHeaders ?? {},
        // Support both old and new recipient formats for backwards compatibility
        receiverAddressByNetwork: body.receiverAddressByNetwork ?? {},
        recipient: body.recipient ?? undefined,
        tools: Array.isArray(body.tools) ? body.tools : [],
        metadata: body.metadata ?? {},
    } as StoredServerConfig;

    try {
        const saved = await redisStore.upsertServerConfig(input as StoredServerConfig);
        // No console logging
        return c.json({ ok: true, id: saved.id });
    } catch (error) {
        // No console logging
        return c.json({ error: "failed_to_save" }, 500);
    }
});

// Get the public URL for mcp2 monetization proxy
const MCP2_PUBLIC_URL = process.env.MCP2_PUBLIC_URL ?? 'http://localhost:3006';

// Helper: Build payment annotations for a tool using centralized constants
function buildToolAnnotations(
    tool: { name: string; pricing?: string },
    server: { recipient?: { evm?: { address: string } }; metadata?: Record<string, unknown> }
): Record<string, unknown> | undefined {
    const pricing = tool.pricing;
    if (!pricing || typeof pricing !== 'string' || !pricing.startsWith('$')) {
        return undefined;
    }

    const priceValue = parseFloat(pricing.substring(1));
    if (isNaN(priceValue) || priceValue <= 0) {
        return undefined;
    }

    // Build payment networks info
    const paymentNetworks: Array<{
        network: string;
        recipient: string;
        maxAmountRequired: string;
        asset: { address: string; symbol: string; decimals: number };
        type: 'evm';
    }> = [];

    // Get networks from metadata or default to Cronos testnet
    const selectedNetworks = (server.metadata?.networks as string[]) || [CRONOS_NETWORK.TESTNET];
    const recipientAddress = server.recipient?.evm?.address;

    if (recipientAddress) {
        for (const network of selectedNetworks) {
            // Only include Cronos networks using centralized check
            if (isCronosNetwork(network)) {
                // Map network name to CronosAssets key
                const assetKey = network === CRONOS_NETWORK.TESTNET ? 'cronos-testnet' : 'cronos-mainnet';
                const usdcAsset = CronosAssets[assetKey as keyof typeof CronosAssets]?.['USDC.e'];

                if (usdcAsset) {
                    paymentNetworks.push({
                        network,
                        recipient: recipientAddress,
                        maxAmountRequired: String(Math.floor(priceValue * Math.pow(10, usdcAsset.decimals))),
                        asset: {
                            address: usdcAsset.address,
                            symbol: usdcAsset.symbol,
                            decimals: usdcAsset.decimals,
                        },
                        type: 'evm',
                    });
                }
            }
        }
    }

    return {
        paymentHint: true,
        paymentPriceUSD: priceValue,
        paymentNetworks,
        paymentVersion: 1,
    };
}

// Admin: list or fetch stored servers (with pagination for frontend compatibility)
app.get("/servers", async (c) => {
    try {
        const url = new URL(c.req.url);
        const limit = parseInt(url.searchParams.get("limit") || "12");
        const offset = parseInt(url.searchParams.get("offset") || "0");

        // Load all servers from Redis
        const store = await redisStore.loadStore();
        const allServers = Object.values(store.serversById);

        // Convert to frontend-expected format
        // IMPORTANT: origin should be the mcp2 monetization URL, not the direct upstream
        // This ensures requests go through the X402 payment hook
        const formattedServers = allServers.map(server => ({
            id: server.id,
            origin: `${MCP2_PUBLIC_URL}/mcp?id=${server.id}`, // Monetization proxy URL
            originRaw: server.mcpOrigin, // Keep original for reference
            status: 'active',
            moderation_status: 'approved' as const,
            quality_score: 100,
            last_seen_at: new Date().toISOString(),
            tools: (server.tools || []).map(t => ({
                name: t.name,
                description: `Tool: ${t.name}`,
                pricing: t.pricing,
                annotations: buildToolAnnotations(t, server),
            })),
            server: {
                info: {
                    name: (server.metadata?.name as string) || server.id,
                    description: (server.metadata?.description as string) || `MCP Server: ${server.id}`,
                    icon: '',
                }
            }
        }));

        // Apply pagination
        const paginatedServers = formattedServers.slice(offset, offset + limit);
        const total = formattedServers.length;
        const hasMore = offset + limit < total;

        return c.json({
            servers: paginatedServers,
            total,
            limit,
            offset,
            nextOffset: hasMore ? offset + limit : null,
            hasMore,
        });
    } catch (error) {
        // No console logging
        return c.json({ error: "failed_to_list" }, 500);
    }
});

// Get single server by ID (rich payload for frontend)
app.get("/server/:id", async (c) => {
    try {
        const id = c.req.param("id");
        const server = await redisStore.getServerById(id);

        if (!server) {
            return c.json({ error: "not_found" }, 404);
        }

        // Return rich payload matching frontend expectations
        // IMPORTANT: origin should be the mcp2 monetization URL for X402 payment flow
        return c.json({
            serverId: server.id,
            origin: `${MCP2_PUBLIC_URL}/mcp?id=${server.id}`, // Monetization proxy URL
            originRaw: server.mcpOrigin, // Keep original upstream for reference
            status: 'active',
            moderationStatus: 'approved',
            qualityScore: 100,
            lastSeenAt: new Date().toISOString(),
            indexedAt: new Date().toISOString(),
            info: {
                name: (server.metadata?.name as string) || server.id,
                description: (server.metadata?.description as string) || `MCP Server: ${server.id}`,
                icon: '',
            },
            tools: (server.tools || []).map(t => ({
                name: t.name,
                description: `Tool: ${t.name}`,
                pricing: t.pricing,
                annotations: buildToolAnnotations(t, server),
            })),
            summary: {
                lastActivity: new Date().toISOString(),
                totalTools: (server.tools || []).length,
                totalRequests: await redisStore.getRpcLogsCount(server.id),
                totalPayments: await redisStore.getPaymentsCount(server.id),
            },
            dailyAnalytics: [], // No analytics yet
            // Get payments from both direct recording AND log detection
            recentPayments: await redisStore.getAllPayments(server.id, 20),
        });
    } catch (error) {
        return c.json({ error: "failed_to_get" }, 500);
    }
});

// Explorer endpoint (stats/analytics - stub for now)
app.get("/explorer", async (c) => {
    try {
        const url = new URL(c.req.url);
        const limit = parseInt(url.searchParams.get("limit") || "20");
        const offset = parseInt(url.searchParams.get("offset") || "0");

        // Return empty stats for now - can be enhanced later with actual tracking
        return c.json({
            stats: [],
            total: 0,
            limit,
            offset,
            nextOffset: null,
            hasMore: false,
        });
    } catch (error) {
        return c.json({ error: "failed_to_get_explorer" }, 500);
    }
});

// Ingest RPC logs for payment detection (for external clients/CLI)
app.post("/ingest/rpc", async (c) => {
    try {
        const body = await c.req.json();
        const { serverId, method, toolName, request, response, meta } = body;

        if (!serverId) {
            return c.json({ error: "serverId is required" }, 400);
        }

        // Store the log
        const log = await redisStore.storeRpcLog({
            serverId,
            method,
            toolName,
            request,
            response,
            meta,
        });

        // Check if this log contains a payment
        const payment = redisStore.detectPaymentFromLog(log);
        if (payment) {
            // Also store as direct payment for faster retrieval
            await redisStore.recordPayment({
                serverId: payment.serverId,
                toolName: payment.toolName,
                transactionHash: payment.transactionHash,
                network: payment.network,
                payer: payment.payer,
                amount: payment.amount,
                currency: payment.currency,
                status: payment.status,
                settledAt: payment.settledAt,
            });
            console.log(`[Ingest] Payment detected and recorded: ${payment.transactionHash}`);
        }

        return c.json({
            success: true,
            logId: log.id,
            paymentDetected: !!payment,
        });
    } catch (error) {
        console.error("[Ingest] Error:", error);
        return c.json({ error: "failed_to_ingest" }, 500);
    }
});

// Trigger indexing of an MCP server (stub - for frontend compatibility)
app.post("/index/run", async (c) => {
    try {
        const body = await c.req.json().catch(() => null) as { origin?: string };

        if (!body?.origin) {
            return c.json({ error: "missing_origin" }, 400);
        }

        // Check if server exists by origin
        const server = await redisStore.getServerByOrigin(body.origin);

        if (server) {
            return c.json({ ok: true, serverId: server.id });
        }

        // For now, just return ok - indexing would require fetching and parsing the MCP server
        return c.json({ ok: true, message: "Server not found, registration required" });
    } catch (error) {
        return c.json({ error: "failed_to_index" }, 500);
    }
});

// app.get("/servers/:id", async (c) => {
//     const id = c.req.param("id");
//     try {
//         const s = id ? await redisStore.getServerById(id) : null;
//         if (!s) return c.json({ error: "not_found" }, 404);

//         // Hide mcpOrigin and authHeaders
//         const { mcpOrigin, authHeaders, ...rest } = s;
//         return c.json(rest);
//     } catch (error) {
//         console.error(`[${new Date().toISOString()}] Error getting server:`, error);
//         return c.json({ error: "failed_to_get" }, 500);
//     }
// });

// Proxy endpoint: /mcp?id=<ID>
app.all("/mcp", async (c) => {
    const original = c.req.raw;
    const targetUrl = await resolveTargetUrl(original, c.req.url);
    console.log('[Proxy] targetUrl resolved:', targetUrl);

    let prices: Record<string, Price> = {};
    let recipient: Partial<Record<Network, string>> | { evm: RecipientWithTestnet } = {
        evm: { address: "0x0000000000000000000000000000000000000000", isTestnet: false },
    };

    if (targetUrl) {
        const monetization = await buildMonetizationForTarget(targetUrl);
        console.log('[Proxy] monetization result:', JSON.stringify(monetization, null, 2));
        if (monetization && Object.keys(monetization.prices).length > 0) {
            prices = monetization.prices;
            recipient = monetization.recipient;
            console.log('[Proxy] Using prices:', JSON.stringify(prices));
            console.log('[Proxy] Using recipient:', JSON.stringify(recipient));
        } else {
            console.log('[Proxy] No monetization config found or empty prices');
        }
    }

    // Use Hono's absolute URL instead of original.url which might be relative
    const currentUrl = new URL(c.req.url);
    const serverId = currentUrl.searchParams.get("id");
    if (!serverId) {
        return new Response("server-id missing", { status: 400 });
    }

    // Ensure the proxy receives a base64 target-url header
    const headers = new Headers(original.headers);
    if (targetUrl && !headers.get("x-cronos402-target-url")) {
        headers.set("x-cronos402-target-url", btoa(targetUrl));
    }

    // Use absolute URL from Hono context instead of original.url which might be relative
    const reqForProxy = new Request(c.req.url, {
        method: original.method,
        headers,
        body: original.body,
        duplex: 'half'
    } as RequestInit);

    if (!targetUrl) {
        return new Response("target-url missing", { status: 400 });
    }

    // Use Cronos facilitator for x402 payments
    const CRONOS_FACILITATOR_URL = "https://facilitator.cronoslabs.org/v2/x402";

    // Analytics sink - automatically captures ALL tool calls and stores to Redis
    const analyticsSink = async (event: Record<string, unknown>) => {
        try {
            const meta = event.meta as { res?: unknown; req?: unknown } | undefined;
            const toolName = (meta?.req as { params?: { name?: string } })?.params?.name;

            // Store the RPC log
            const log = await redisStore.storeRpcLog({
                serverId: serverId,
                method: event.method as string,
                toolName: toolName,
                request: meta?.req,
                response: meta?.res,
                meta: event,
            });

            // Detect and record payment from the log
            const payment = redisStore.detectPaymentFromLog(log);
            if (payment && payment.transactionHash) {
                // Check if we already recorded this payment (avoid duplicates with onPaymentSettled)
                const existing = await redisStore.getRecentPayments(serverId, 50);
                const alreadyRecorded = existing.some(p => p.transactionHash === payment.transactionHash);
                if (!alreadyRecorded) {
                    await redisStore.recordPayment(payment);
                    console.log(`[AnalyticsSink] Payment detected and recorded: ${payment.transactionHash}`);
                }
            }
        } catch (err) {
            console.error('[AnalyticsSink] Error:', err);
        }
    };

    const proxy = withProxy(targetUrl, [
        new LoggingHook(),
        new X402MonetizationHook({
            recipient: recipient,
            prices,
            facilitator: {
                url: CRONOS_FACILITATOR_URL,
            },
            // Record payments to Redis when settled
            onPaymentSettled: async (event) => {
                try {
                    await redisStore.recordPayment({
                        serverId: serverId,
                        toolName: event.toolName,
                        transactionHash: event.transactionHash,
                        network: event.network,
                        payer: event.payer,
                        amount: event.amount,
                        currency: 'USDC',
                        status: event.status,
                        settledAt: new Date().toISOString(),
                    });
                    console.log(`[Proxy] Payment recorded for server ${serverId}: ${event.transactionHash}`);
                } catch (err) {
                    console.error('[Proxy] Failed to record payment:', err);
                }
            },
        }),
        // AnalyticsHook - automatically captures ALL tool calls for logging
        new AnalyticsHook(analyticsSink, targetUrl),
    ]);


    const mcpConfig = await redisStore.getServerById(serverId);
    // No console logging
    
    // Check if auth headers are required and available
    if (mcpConfig?.authHeaders && mcpConfig.requireAuth === true) {
        // Iterate through auth headers and set them in the request headers
        for (const [key, value] of Object.entries(mcpConfig.authHeaders)) {
            if (typeof value === "string" && value.length > 0) {
                headers.set(key, value);
            }
        }

        const reqForProxyWithHeaders = new Request(targetUrl, {
            method: original.method,
            headers: headers,
            body: original.body,
            duplex: 'half'
        } as RequestInit);  

        // No console logging
        return await proxy(reqForProxyWithHeaders);
    } else {
        // No auth headers required or available, proxy original request
        // No console logging
        return await proxy(reqForProxy);
    }
});

const portPromise = getPort({ port: process.env.PORT ? Number(process.env.PORT) : 3006 });
const port = await portPromise;

// Support both Vercel-style export (for serverless) and local node listening
const isVercel = !!process.env.VERCEL;

if (!isVercel) {
    serve({
        fetch: app.fetch,
        port: port,
        hostname: '0.0.0.0' // Important for sandbox access
    }, (info) => {
        // No console logging
    });
}

// For Vercel (Edge/Serverless) export just the app instance
export default isVercel
    ? app
    : {
        app,
        port: port,
    };