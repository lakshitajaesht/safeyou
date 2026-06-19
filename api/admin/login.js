import { json, readJson, setCors } from "../../lib/http.js";
import {
  authConfigured,
  createSessionCookie,
  passwordMatches
} from "../../lib/admin-auth.js";

export default async function handler(req, res) {
  setCors(res);
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.end();
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });
  if (!authConfigured()) {
    return json(res, 503, { error: "Admin login is not configured on the server" });
  }

  try {
    const body = await readJson(req);
    if (!passwordMatches(body.password)) {
      return json(res, 401, { error: "Incorrect password" });
    }
    res.setHeader("Set-Cookie", createSessionCookie(req));
    return json(res, 200, { ok: true });
  } catch {
    return json(res, 400, { error: "Invalid login request" });
  }
}
