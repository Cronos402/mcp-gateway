import { Redis } from 'ioredis';
import { z } from 'zod';
import { config } from 'dotenv';

config();

// Environment variables - simple REDIS_URL like redis://localhost:6379 or redis://:password@host:6379/0
const REDIS_URL = process.env.REDIS_URL ?? 'redis://localhost:6379';
// MCP2 public URL for generating server URLs (defaults to local)
const MCP2_PUBLIC_URL = process.env.MCP2_PUBLIC_URL ?? 'http://localhost:3006';

// Key prefixes for organization
const KEYS = {
  SERVER: 'mcp:server:',
  SERVER_BY_ORIGIN: 'mcp:origin:',
  TOOLS: 'mcp:tools:',
  AUDIT: 'mcp:audit:',
  SERVER_IDS_SET: 'mcp:server_ids',
  PAYMENTS: 'mcp:payments:',
  RPC_LOGS: 'mcp:logs:',
} as const;

// Payment record schema
const PaymentRecordSchema = z.object({
  id: z.string(),
  serverId: z.string(),
  toolName: z.string(),
  transactionHash: z.string().optional(),
  network: z.string(),
  payer: z.string().optional(),
  amount: z.string(),
  currency: z.string().default('USDC'),
  status: z.enum(['completed', 'failed', 'pending']),
  createdAt: z.string(),
  settledAt: z.string().optional(),
});

export type PaymentRecord = z.infer<typeof PaymentRecordSchema>;

// RPC Log schema for storing request/response pairs
const RpcLogSchema = z.object({
  id: z.string(),
  serverId: z.string(),
  method: z.string().optional(),
  toolName: z.string().optional(),
  request: z.unknown(),
  response: z.unknown(),
  meta: z.record(z.string(), z.unknown()).optional(),
  timestamp: z.string(),
});

export type RpcLog = z.infer<typeof RpcLogSchema>;

// Validation schemas
const StoredToolSchema = z.object({
  name: z.string(),
  pricing: z.string(),
});

const RecipientSchema = z.object({
  evm: z.object({
    address: z.string(),
    isTestnet: z.boolean().optional(),
  }).optional(),
  svm: z.object({
    address: z.string(),
    isTestnet: z.boolean().optional(),
  }).optional(),
});

const StoredServerConfigSchema = z.object({
  id: z.string(),
  mcpOrigin: z.string(),
  requireAuth: z.boolean().optional(),
  authHeaders: z.record(z.string(), z.string()).optional(),
  receiverAddressByNetwork: z.record(z.string(), z.string()).optional(),
  recipient: RecipientSchema.optional(),
  tools: z.array(StoredToolSchema).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

const StoreShapeSchema = z.object({
  serversById: z.record(z.string(), StoredServerConfigSchema),
  serverIdByOrigin: z.record(z.string(), z.string()),
});

// Types
export type StoredTool = z.infer<typeof StoredToolSchema>;
export type StoredServerConfig = z.infer<typeof StoredServerConfigSchema>;
export type StoreShape = z.infer<typeof StoreShapeSchema>;

// Redis store class using ioredis
export class RedisMcpStore {
  private redis: Redis;

  constructor(redisUrl?: string) {
    this.redis = new Redis(redisUrl || REDIS_URL);
  }

  // Initialize Redis connection
  async connect(): Promise<void> {
    try {
      await this.redis.ping();
      console.log(`[${new Date().toISOString()}] Redis connected successfully`);
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Redis connection failed:`, error);
      throw error;
    }
  }

  // Load all data from Redis
  async loadStore(): Promise<StoreShape> {
    try {
      let serverIds = await this.redis.smembers(KEYS.SERVER_IDS_SET);

      if (serverIds.length === 0) {
        console.log(`[${new Date().toISOString()}] SERVER_IDS_SET is empty, migrating existing data...`);
        await this.migrateExistingServersToSet();
        serverIds = await this.redis.smembers(KEYS.SERVER_IDS_SET);
      }

      const serversById: Record<string, StoredServerConfig> = {};
      const serverIdByOrigin: Record<string, string> = {};

      for (const serverId of serverIds) {
        const serverData = await this.redis.get(`${KEYS.SERVER}${serverId}`);

        if (serverData) {
          try {
            const parsed = JSON.parse(serverData);
            const validated = StoredServerConfigSchema.parse(parsed);
            serversById[serverId] = validated;
            serverIdByOrigin[validated.mcpOrigin] = serverId;
          } catch (error) {
            console.warn(`[${new Date().toISOString()}] Invalid server data for ${serverId}:`, error);
          }
        }
      }

      console.log(`[${new Date().toISOString()}] Loaded ${Object.keys(serversById).length} servers from Redis`);
      return { serversById, serverIdByOrigin };
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error loading store from Redis:`, error);
      return { serversById: {}, serverIdByOrigin: {} };
    }
  }

  // Save server configuration
  async upsertServerConfig(input: Partial<StoredServerConfig> & { id: string; mcpOrigin: string }): Promise<StoredServerConfig> {
    try {
      const existingData = await this.redis.get(`${KEYS.SERVER}${input.id}`);
      const current = existingData ? JSON.parse(existingData) : { id: input.id, mcpOrigin: input.mcpOrigin };

      const merged: StoredServerConfig = {
        ...current,
        ...input,
        authHeaders: { ...(current.authHeaders ?? {}), ...(input.authHeaders ?? {}) },
        receiverAddressByNetwork: { ...(current.receiverAddressByNetwork ?? {}), ...(input.receiverAddressByNetwork ?? {}) },
        recipient: input.recipient ?? current.recipient,
        tools: input.tools ?? current.tools ?? [],
        metadata: { ...(current.metadata ?? {}), ...(input.metadata ?? {}) },
      };

      const validated = StoredServerConfigSchema.parse(merged);
      const expirationSeconds = 30 * 24 * 60 * 60; // 30 days

      const pipeline = this.redis.pipeline();
      pipeline.setex(`${KEYS.SERVER}${merged.id}`, expirationSeconds, JSON.stringify(validated));
      pipeline.setex(`${KEYS.SERVER_BY_ORIGIN}${merged.mcpOrigin}`, expirationSeconds, merged.id);
      pipeline.sadd(KEYS.SERVER_IDS_SET, merged.id);

      if (merged.tools && merged.tools.length > 0) {
        pipeline.setex(`${KEYS.TOOLS}${merged.id}`, expirationSeconds, JSON.stringify(merged.tools));
      }

      await pipeline.exec();
      await this.logAudit('upsert', 'server', merged.id, { action: 'upsert_server', serverId: merged.id });

      return validated;
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error upserting server config:`, error);
      throw error;
    }
  }

  // Get server by ID
  async getServerById(id: string): Promise<StoredServerConfig | null> {
    try {
      const data = await this.redis.get(`${KEYS.SERVER}${id}`);
      if (!data) return null;

      return StoredServerConfigSchema.parse(JSON.parse(data));
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error getting server by ID:`, error);
      return null;
    }
  }

  // Get server by origin
  async getServerByOrigin(origin: string): Promise<StoredServerConfig | null> {
    try {
      const serverId = await this.redis.get(`${KEYS.SERVER_BY_ORIGIN}${origin}`);
      if (!serverId) return null;

      return await this.getServerById(serverId);
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error getting server by origin:`, error);
      return null;
    }
  }

  // Get all servers (for listing)
  async getAllServers(): Promise<Array<{ id: string; url: string }>> {
    try {
      let serverIds = await this.redis.smembers(KEYS.SERVER_IDS_SET);

      if (serverIds.length === 0) {
        console.log(`[${new Date().toISOString()}] SERVER_IDS_SET is empty, migrating existing data...`);
        await this.migrateExistingServersToSet();
        serverIds = await this.redis.smembers(KEYS.SERVER_IDS_SET);
      }

      const servers = [];

      for (const serverId of serverIds) {
        const server = await this.getServerById(serverId);
        if (server) {
          servers.push({
            id: serverId,
            url: `${MCP2_PUBLIC_URL}/mcp?id=${serverId}`
          });
        }
      }

      return servers;
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error getting all servers:`, error);
      return [];
    }
  }

  // Delete server
  async deleteServer(id: string): Promise<boolean> {
    try {
      const server = await this.getServerById(id);
      if (!server) return false;

      const pipeline = this.redis.pipeline();
      pipeline.del(`${KEYS.SERVER}${id}`);
      pipeline.del(`${KEYS.SERVER_BY_ORIGIN}${server.mcpOrigin}`);
      pipeline.del(`${KEYS.TOOLS}${id}`);
      pipeline.srem(KEYS.SERVER_IDS_SET, id);

      await pipeline.exec();
      await this.logAudit('delete', 'server', id, { action: 'delete_server', serverId: id });
      return true;
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error deleting server:`, error);
      return false;
    }
  }

  // Migrate existing servers to use the SERVER_IDS_SET
  private async migrateExistingServersToSet(): Promise<void> {
    try {
      console.log(`[${new Date().toISOString()}] Starting migration of existing servers to SERVER_IDS_SET...`);

      const serverKeys = await this.redis.keys(`${KEYS.SERVER}*`);

      if (serverKeys.length === 0) {
        console.log(`[${new Date().toISOString()}] No existing servers found to migrate`);
        return;
      }

      const serverIds = serverKeys.map((key: string) => key.replace(KEYS.SERVER, ''));

      if (serverIds.length > 0) {
        await this.redis.sadd(KEYS.SERVER_IDS_SET, ...serverIds);
        console.log(`[${new Date().toISOString()}] Migrated ${serverIds.length} servers to SERVER_IDS_SET`);
      }
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error migrating existing servers:`, error);
    }
  }

  // Audit logging
  async logAudit(action: string, tableName: string, recordId: string, details?: any): Promise<void> {
    try {
      const auditEntry = {
        action,
        tableName,
        recordId,
        timestamp: new Date().toISOString(),
        details: details ? JSON.stringify(details) : null,
      };

      await this.redis.lpush(`${KEYS.AUDIT}${Date.now()}`, JSON.stringify(auditEntry));
      await this.redis.ltrim(KEYS.AUDIT, 0, 999);
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error logging audit:`, error);
    }
  }

  // Health check
  async healthCheck(): Promise<boolean> {
    try {
      const result = await this.redis.ping();
      return result === 'PONG';
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Redis health check failed:`, error);
      return false;
    }
  }

  // ==================== PAYMENT TRACKING ====================

  async recordPayment(payment: Omit<PaymentRecord, 'id' | 'createdAt'>): Promise<PaymentRecord> {
    try {
      const id = `pay_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
      const createdAt = new Date().toISOString();

      const record: PaymentRecord = { ...payment, id, createdAt };
      PaymentRecordSchema.parse(record);

      const key = `${KEYS.PAYMENTS}${payment.serverId}`;
      const score = Date.now();

      await this.redis.zadd(key, score, JSON.stringify(record));
      await this.redis.zremrangebyrank(key, 0, -101);

      console.log(`[${new Date().toISOString()}] Payment recorded: ${id} for server ${payment.serverId}`);
      return record;
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error recording payment:`, error);
      throw error;
    }
  }

  async getRecentPayments(serverId: string, limit: number = 20): Promise<PaymentRecord[]> {
    try {
      const key = `${KEYS.PAYMENTS}${serverId}`;
      const results = await this.redis.zrevrange(key, 0, limit - 1);

      const payments: PaymentRecord[] = [];
      for (const item of results) {
        try {
          payments.push(PaymentRecordSchema.parse(JSON.parse(item)));
        } catch (e) {
          console.warn(`[${new Date().toISOString()}] Invalid payment record:`, e);
        }
      }

      return payments;
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error getting recent payments:`, error);
      return [];
    }
  }

  async getPaymentsCount(serverId: string): Promise<number> {
    try {
      return await this.redis.zcard(`${KEYS.PAYMENTS}${serverId}`);
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error getting payments count:`, error);
      return 0;
    }
  }

  // ==================== RPC LOG TRACKING ====================

  async storeRpcLog(log: Omit<RpcLog, 'id' | 'timestamp'>): Promise<RpcLog> {
    try {
      const id = `log_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
      const timestamp = new Date().toISOString();

      const record: RpcLog = { ...log, id, timestamp };
      const key = `${KEYS.RPC_LOGS}${log.serverId}`;
      const score = Date.now();

      await this.redis.zadd(key, score, JSON.stringify(record));
      await this.redis.zremrangebyrank(key, 0, -501);

      return record;
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error storing RPC log:`, error);
      throw error;
    }
  }

  async getRecentLogs(serverId: string, limit: number = 100): Promise<RpcLog[]> {
    try {
      const key = `${KEYS.RPC_LOGS}${serverId}`;
      const results = await this.redis.zrevrange(key, 0, limit - 1);

      const logs: RpcLog[] = [];
      for (const item of results) {
        try {
          logs.push(RpcLogSchema.parse(JSON.parse(item)));
        } catch (e) {
          // Skip invalid logs
        }
      }

      return logs;
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error getting RPC logs:`, error);
      return [];
    }
  }

  async getRpcLogsCount(serverId: string): Promise<number> {
    try {
      return await this.redis.zcard(`${KEYS.RPC_LOGS}${serverId}`);
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error getting RPC logs count:`, error);
      return 0;
    }
  }

  detectPaymentFromLog(log: RpcLog): PaymentRecord | null {
    try {
      const response = log.response as Record<string, unknown> | undefined;
      if (!response) return null;

      const resMeta = response._meta as Record<string, unknown> | undefined;
      if (!resMeta) return null;

      const paymentResponse = resMeta['x402/payment-response'] as Record<string, unknown> | undefined;
      if (!paymentResponse || !paymentResponse.success) return null;

      const transaction = paymentResponse.transaction as string | undefined;
      const network = paymentResponse.network as string | undefined;
      const payer = paymentResponse.payer as string | undefined;

      const request = log.request as Record<string, unknown> | undefined;
      const params = request?.params as Record<string, unknown> | undefined;
      const reqMeta = params?._meta as Record<string, unknown> | undefined;
      const paymentToken = reqMeta?.['x402/payment'] as string | undefined;

      let amount = '0';
      if (paymentToken) {
        try {
          const decoded = JSON.parse(Buffer.from(paymentToken, 'base64').toString('utf-8'));
          amount = decoded?.payload?.value || '0';
        } catch {
          // Use default
        }
      }

      return {
        id: `pay_${log.id}`,
        serverId: log.serverId,
        toolName: log.toolName || 'unknown',
        transactionHash: transaction,
        network: network || 'cronos-testnet',
        payer,
        amount,
        currency: 'USDC',
        status: 'completed',
        createdAt: log.timestamp,
        settledAt: log.timestamp,
      };
    } catch (error) {
      return null;
    }
  }

  async detectPaymentsFromLogs(serverId: string, limit: number = 100): Promise<PaymentRecord[]> {
    const logs = await this.getRecentLogs(serverId, limit);
    const payments: PaymentRecord[] = [];

    for (const log of logs) {
      const payment = this.detectPaymentFromLog(log);
      if (payment) {
        payments.push(payment);
      }
    }

    return payments;
  }

  async getAllPayments(serverId: string, limit: number = 20): Promise<PaymentRecord[]> {
    const directPayments = await this.getRecentPayments(serverId, limit);
    const logPayments = await this.detectPaymentsFromLogs(serverId, limit * 2);

    const paymentMap = new Map<string, PaymentRecord>();

    for (const p of directPayments) {
      const key = p.transactionHash || p.id;
      paymentMap.set(key, p);
    }

    for (const p of logPayments) {
      const key = p.transactionHash || p.id;
      if (!paymentMap.has(key)) {
        paymentMap.set(key, p);
      }
    }

    return Array.from(paymentMap.values())
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, limit);
  }

  // Close connection
  async disconnect(): Promise<void> {
    try {
      await this.redis.quit();
      console.log(`[${new Date().toISOString()}] Redis disconnected`);
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error disconnecting Redis:`, error);
    }
  }
}

// Export singleton instance
export const redisStore = new RedisMcpStore();
export default redisStore;
