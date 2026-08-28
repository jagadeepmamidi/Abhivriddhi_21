import { randomUUID } from "node:crypto";
import { sha256 } from "@/lib/crypto";
import { insertAudit, latestAuditHash, listAllAuditLogs, type AuditRow } from "@/lib/db";

export type AuditInput = {
  userId: string;
  action: string;
  dataHash: string;
  method?: string | null;
  redactionLevel?: string | null;
  encryptionUsed?: boolean;
  domain?: string | null;
  entityTypes?: string[] | null;
};

function computeChainHash(input: {
  previousHash: string;
  userId: string;
  action: string;
  dataHash: string;
  createdAt: string;
  method?: string | null;
}): string {
  return sha256(
    [
      input.previousHash,
      input.userId,
      input.action,
      input.dataHash,
      input.createdAt,
      input.method ?? "",
    ].join("|"),
  );
}

export function appendAuditLog(input: AuditInput): AuditRow {
  const createdAt = new Date().toISOString();
  const previousHash = latestAuditHash();
  const chainHash = computeChainHash({
    previousHash,
    userId: input.userId,
    action: input.action,
    dataHash: input.dataHash,
    createdAt,
    method: input.method,
  });
  const row: AuditRow = {
    id: randomUUID(),
    user_id: input.userId,
    action: input.action,
    data_hash: input.dataHash,
    method: input.method ?? null,
    redaction_level: input.redactionLevel ?? null,
    encryption_used: input.encryptionUsed ? 1 : 0,
    domain: input.domain ?? null,
    entity_types: input.entityTypes ? JSON.stringify(input.entityTypes) : null,
    previous_hash: previousHash,
    chain_hash: chainHash,
    created_at: createdAt,
  };
  insertAudit(row);
  return row;
}

export function verifyAuditChain(): { valid: boolean; checked: number; brokenAt: string | null } {
  const logs = listAllAuditLogs();
  let previous = "0".repeat(64);
  for (const log of logs) {
    if (log.previous_hash !== previous) {
      return { valid: false, checked: logs.length, brokenAt: log.id };
    }
    const expected = computeChainHash({
      previousHash: log.previous_hash,
      userId: log.user_id,
      action: log.action,
      dataHash: log.data_hash,
      createdAt: log.created_at,
      method: log.method,
    });
    if (expected !== log.chain_hash) {
      return { valid: false, checked: logs.length, brokenAt: log.id };
    }
    previous = log.chain_hash;
  }
  return { valid: true, checked: logs.length, brokenAt: null };
}
