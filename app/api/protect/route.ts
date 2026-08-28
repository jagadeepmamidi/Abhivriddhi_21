import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { z } from "zod";
import { errorResponse, requireUser } from "@/lib/api";
import { appendAuditLog } from "@/lib/audit";
import { encryptText, sha256 } from "@/lib/crypto";
import { insertDownload } from "@/lib/db";
import { protectText } from "@/lib/protect";
import { ENTITY_TYPES, PROTECTION_METHODS, REDACTION_LEVELS, DOMAINS } from "@/lib/types";

const schema = z.object({
  text: z.string().min(1).max(200_000),
  method: z.enum(PROTECTION_METHODS),
  entityTypes: z.array(z.enum(ENTITY_TYPES)).default(["PERSON", "ORG", "GPE", "DATE", "EMAIL"]),
  customWords: z.array(z.string()).optional(),
  redactionLevel: z.enum(REDACTION_LEVELS).optional(),
  domain: z.enum(DOMAINS).optional(),
  useEncryption: z.boolean().optional(),
  filename: z.string().optional(),
});

export async function POST(request: Request) {
  const auth = await requireUser();
  if (!auth.user) return auth.response;
  try {
    const body = schema.parse(await request.json());
    const result = protectText(body.text, {
      method: body.method,
      entityTypes: body.entityTypes,
      customWords: body.customWords,
      redactionLevel: body.redactionLevel,
      domain: body.domain,
    });
    const dataHash = sha256(result.processed);
    let encryption: { key: string; ciphertext: string } | null = null;
    if (body.useEncryption) {
      encryption = encryptText(body.text);
    }
    const audit = appendAuditLog({
      userId: auth.user.id,
      action: body.method,
      dataHash,
      method: body.method,
      redactionLevel: body.redactionLevel,
      encryptionUsed: Boolean(body.useEncryption),
      domain: body.domain,
      entityTypes: body.entityTypes,
    });
    const filename =
      body.filename ??
      `${body.method}_${new Date().toISOString().replace(/[:.]/g, "-")}.txt`;
    insertDownload({
      id: randomUUID(),
      user_id: auth.user.id,
      filename,
      mime: "text/plain; charset=utf-8",
      content: Buffer.from(result.processed, "utf8"),
      created_at: new Date().toISOString(),
    });
    return NextResponse.json({
      processed: result.processed,
      counts: result.counts,
      spans: result.spans,
      dataHash,
      auditId: audit.id,
      encryption,
      filename,
    });
  } catch (error) {
    return errorResponse(error);
  }
}
