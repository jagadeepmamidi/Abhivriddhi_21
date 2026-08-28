import { NextResponse } from "next/server";
import { z } from "zod";
import { registerUser, signupSchema } from "@/lib/auth";
import { setSessionCookie } from "@/lib/session";

export async function POST(request: Request) {
  try {
    const body = signupSchema.parse(await request.json());
    const user = registerUser(body);
    await setSessionCookie(user);
    return NextResponse.json({ user });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues[0]?.message ?? "Invalid input" }, { status: 400 });
    }
    const message = error instanceof Error ? error.message : "Could not create account";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
