import { clearSessionCookie } from "../../lib/admin-auth.js";
import { json } from "../../lib/http.js";

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });
  res.setHeader("Set-Cookie", clearSessionCookie(req));
  return json(res, 200, { ok: true });
}
