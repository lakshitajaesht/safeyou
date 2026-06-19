import {
  createHmac,
  timingSafeEqual
} from "node:crypto";

const COOKIE_NAME = "safeyou_admin";
const SESSION_AGE_SECONDS = 8 * 60 * 60;

function secret() {
  return process.env.ADMIN_SESSION_SECRET || "";
}

function encode(value) {
  return Buffer.from(value).toString("base64url");
}

function sign(payload) {
  return createHmac("sha256", secret()).update(payload).digest("base64url");
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function cookies(req) {
  return Object.fromEntries(
    String(req.headers?.cookie || "")
      .split(";")
      .map((part) => part.trim().split("="))
      .filter(([name, value]) => name && value)
  );
}

export function authConfigured() {
  return Boolean(process.env.ADMIN_PASSWORD && secret());
}

export function passwordMatches(password) {
  return authConfigured() && safeEqual(password, process.env.ADMIN_PASSWORD);
}

export function createSessionCookie(req) {
  const payload = encode(JSON.stringify({
    role: "admin",
    expiresAt: Date.now() + SESSION_AGE_SECONDS * 1000
  }));
  const secure = req.headers?.["x-forwarded-proto"] === "https";
  return [
    `${COOKIE_NAME}=${payload}.${sign(payload)}`,
    "HttpOnly",
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${SESSION_AGE_SECONDS}`,
    secure ? "Secure" : ""
  ].filter(Boolean).join("; ");
}

export function clearSessionCookie(req) {
  const secure = req.headers?.["x-forwarded-proto"] === "https";
  return [
    `${COOKIE_NAME}=`,
    "HttpOnly",
    "SameSite=Strict",
    "Path=/",
    "Max-Age=0",
    secure ? "Secure" : ""
  ].filter(Boolean).join("; ");
}

export function isAdmin(req) {
  if (!authConfigured()) return false;
  const token = cookies(req)[COOKIE_NAME];
  if (!token) return false;
  const [payload, signature] = token.split(".");
  if (!payload || !signature || !safeEqual(signature, sign(payload))) return false;

  try {
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return session.role === "admin" && session.expiresAt > Date.now();
  } catch {
    return false;
  }
}

export function requireAdmin(req, res, json) {
  if (isAdmin(req)) return true;
  json(res, 401, { error: "Authentication required" });
  return false;
}
