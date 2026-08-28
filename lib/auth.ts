import { z } from "zod";
import { createUser, findUserByEmail, verifyPassword } from "@/lib/db";
import type { PublicUser } from "@/lib/types";

export const signupSchema = z.object({
  username: z.string().trim().min(2).max(40),
  email: z.string().trim().email().max(120),
  password: z.string().min(8).max(72),
});

export const loginSchema = z.object({
  email: z.string().trim().email(),
  password: z.string().min(1).max(72),
});

export function toPublicUser(user: { id: string; username: string; email: string }): PublicUser {
  return { id: user.id, username: user.username, email: user.email };
}

export function registerUser(input: z.infer<typeof signupSchema>): PublicUser {
  const existing = findUserByEmail(input.email);
  if (existing) {
    throw new Error("An account with that email already exists");
  }
  const user = createUser(input.username, input.email, input.password);
  return toPublicUser(user);
}

export function authenticateUser(input: z.infer<typeof loginSchema>): PublicUser {
  const user = findUserByEmail(input.email);
  if (!user || !verifyPassword(user, input.password)) {
    throw new Error("Invalid email or password");
  }
  return toPublicUser(user);
}
