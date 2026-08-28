import { NextResponse } from "next/server";
import { z } from "zod";
import { errorResponse, requireUser } from "@/lib/api";
import { decryptText } from "@/lib/crypto";

const schema = z.object({
  ciphertext: z.string().min(1),
  key: z.string().min(1),
});

export async function POST(request: Request) {
  const auth = await requireUser();
  if (!auth.user) return auth.response;
  try {
    const body = schema.parse(await request.json());
    const text = decryptText(body.ciphertext, body.key);
    return NextResponse.json({ text });
  } catch (error) {
    return errorResponse(error, "Decryption failed");
  }
}
