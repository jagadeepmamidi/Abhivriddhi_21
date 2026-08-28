import { NextResponse } from "next/server";
import { z } from "zod";
import { errorResponse, requireUser } from "@/lib/api";
import { analyzeText } from "@/lib/protect";

const schema = z.object({
  text: z.string().min(1).max(200_000),
});

export async function POST(request: Request) {
  const auth = await requireUser();
  if (!auth.user) return auth.response;
  try {
    const body = schema.parse(await request.json());
    return NextResponse.json({ counts: analyzeText(body.text) });
  } catch (error) {
    return errorResponse(error);
  }
}
