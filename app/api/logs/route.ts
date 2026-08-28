import { NextResponse } from "next/server";
import { errorResponse, requireUser } from "@/lib/api";
import { listAuditLogs } from "@/lib/db";

export async function GET() {
  const auth = await requireUser();
  if (!auth.user) return auth.response;
  try {
    const logs = listAuditLogs(auth.user.id).map((log) => ({
      id: log.id,
      action: log.action,
      dataHash: log.data_hash,
      method: log.method,
      redactionLevel: log.redaction_level,
      encryptionUsed: Boolean(log.encryption_used),
      domain: log.domain,
      entityTypes: log.entity_types ? JSON.parse(log.entity_types) : [],
      previousHash: log.previous_hash,
      chainHash: log.chain_hash,
      createdAt: log.created_at,
    }));
    return NextResponse.json({ logs });
  } catch (error) {
    return errorResponse(error);
  }
}
