import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { SESSION_COOKIE, readSessionToken } from "@/lib/session";

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const token = request.cookies.get(SESSION_COOKIE)?.value;
  const user = token ? await readSessionToken(token) : null;

  if (pathname.startsWith("/protect") && !user) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }

  if ((pathname === "/login" || pathname === "/signup") && user) {
    return NextResponse.redirect(new URL("/protect", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/protect/:path*", "/login", "/signup"],
};
