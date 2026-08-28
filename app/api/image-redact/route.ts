import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { errorResponse, requireUser } from "@/lib/api";
import { appendAuditLog } from "@/lib/audit";
import { sha256 } from "@/lib/crypto";
import { insertDownload } from "@/lib/db";
import { IMAGE_EXTENSIONS, extensionOf } from "@/lib/extract";
import { redactImageBuffer } from "@/lib/ocr";

export async function POST(request: Request) {
  const auth = await requireUser();
  if (!auth.user) return auth.response;
  try {
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) {
      return NextResponse.json({ error: "Choose an image to redact" }, { status: 400 });
    }
    const ext = extensionOf(file.name);
    if (!IMAGE_EXTENSIONS.has(ext)) {
      return NextResponse.json({ error: "Use a PNG, JPG, or WEBP image" }, { status: 400 });
    }
    const buffer = Buffer.from(await file.arrayBuffer());
    const result = await redactImageBuffer(buffer);
    const filename = `redacted_${Date.now()}.png`;
    insertDownload({
      id: randomUUID(),
      user_id: auth.user.id,
      filename,
      mime: result.mime,
      content: result.buffer,
      created_at: new Date().toISOString(),
    });
    appendAuditLog({
      userId: auth.user.id,
      action: "image-redaction",
      dataHash: sha256(result.buffer.toString("base64")),
      method: "image-redaction",
    });
    return NextResponse.json({
      filename,
      matches: result.matches,
      image: `data:${result.mime};base64,${result.buffer.toString("base64")}`,
    });
  } catch (error) {
    return errorResponse(error);
  }
}
