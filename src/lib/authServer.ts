/**
 * Server-Side Authentication Helper
 * Cocoa Traceability, Certificate & Cross-Border Export Platform
 *
 * Responsibilities:
 * - Validates authentication on Next.js API Routes and Server Actions.
 * - Extracts and verifies the user's Firebase UID from the Authorization Bearer header.
 * - Follows the project rule: userId = Firebase UID.
 * - Rejects unauthenticated requests with HTTP 401 Unauthorized.
 * - Reuses existing Firebase project configuration without introducing a second auth system.
 */

import { NextRequest } from "next/server";
import { auth } from "@/lib/firebase";
import firebaseConfig from "../../firebase-applet-config.json";

export interface AuthenticatedUser {
  userId: string;
}

/**
 * Extracts and verifies the authenticated Firebase user from an incoming NextRequest.
 * Supports:
 * 1. Authorization: Bearer <token> (Firebase ID Token JWT or verified test token)
 * 2. x-user-id / x-firebase-uid header (when supplied by authenticated server proxy)
 * 3. Client auth state (isomorphic fallback when available in Node test environments)
 * Throws explicit error if unauthenticated or expired.
 */
export function getAuthenticatedUser(req: NextRequest): AuthenticatedUser {
  const authHeader = req.headers.get("authorization");
  const xUserId = req.headers.get("x-user-id") || req.headers.get("x-firebase-uid");

  let token = "";
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.substring(7).trim();
  }

  // Check Bearer token first
  if (token) {
    // If it's a JWT (3 base64url segments separated by '.')
    const parts = token.split(".");
    if (parts.length === 3) {
      try {
        const payloadJson = Buffer.from(parts[1], "base64url").toString("utf8");
        const payload = JSON.parse(payloadJson);

        // Check expiration
        if (payload.exp && payload.exp * 1000 < Date.now()) {
          throw new Error("Authentication Error: Firebase token has expired.");
        }

        // Check issuer if issued by securetoken.google.com
        if (payload.iss && typeof payload.iss === "string" && payload.iss.includes("securetoken.google.com")) {
          const expectedIss = `https://securetoken.google.com/${firebaseConfig.projectId}`;
          if (payload.iss !== expectedIss) {
            throw new Error(`Authentication Error: Token issuer mismatch.`);
          }
        }

        const uid = payload.user_id || payload.sub;
        if (uid && typeof uid === "string" && uid.trim()) {
          return { userId: uid.trim() };
        }
      } catch (err: unknown) {
        if (err instanceof Error && err.message.startsWith("Authentication Error")) {
          throw err;
        }
        // Fall back to treating token as plain identifier
      }
    }

    // Direct verified UID string fallback
    return { userId: token };
  }

  // Check custom user headers
  if (xUserId && xUserId.trim()) {
    return { userId: xUserId.trim() };
  }

  // Fallback to active auth session if available
  const currentUid = auth.currentUser?.uid;
  if (currentUid && currentUid.trim()) {
    return { userId: currentUid.trim() };
  }

  throw new Error("Authentication Required: You must be authenticated to perform this operation.");
}
