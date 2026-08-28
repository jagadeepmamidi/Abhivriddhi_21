import { NextResponse } from "next/server";
import { errorResponse, requireUser } from "@/lib/api";
import { verifyAuditChain } from "@/lib/audit";

export async function GET() {
  const auth = await requireUser();
  if (!auth.user) return auth.response;
  try {
    return NextResponse.json(verifyAuditChain());
  } catch (error) {
    return errorResponse(error);
  }
}
