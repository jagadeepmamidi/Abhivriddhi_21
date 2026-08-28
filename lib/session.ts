import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";
import type { PublicUser } from "@/lib/types";

export const SESSION_COOKIE = "redact_session";

function secretKey() {
  const secret = process.env.SESSION_SECRET;
  if (secret && secret.length >= 32) return new TextEncoder().encode(secret);
  if (process.env.NODE_ENV === "production") {
    throw new Error("SESSION_SECRET must be set to at least 32 characters in production");
  }
  return new TextEncoder().encode("local-dev-redact-session-secret-key!");
}

export async function createSessionToken(user: PublicUser): Promise<string> {
  return new SignJWT({ username: user.username, email: user.email })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(user.id)
    .setIssuedAt()
    .setExpirationTime("14d")
    .sign(secretKey());
}

export async function readSessionToken(token: string): Promise<PublicUser | null> {
  try {
    const { payload } = await jwtVerify(token, secretKey());
    if (!payload.sub || typeof payload.username !== "string" || typeof payload.email !== "string") {
      return null;
    }
    return { id: payload.sub, username: payload.username, email: payload.email };
  } catch {
    return null;
  }
}

export async function setSessionCookie(user: PublicUser) {
  const token = await createSessionToken(user);
  const jar = await cookies();
  jar.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 14,
  });
}

export async function clearSessionCookie() {
  const jar = await cookies();
  jar.delete(SESSION_COOKIE);
}

export async function getCurrentUser(): Promise<PublicUser | null> {
  const jar = await cookies();
  const token = jar.get(SESSION_COOKIE)?.value;
  if (!token) return null;
  return readSessionToken(token);
}
