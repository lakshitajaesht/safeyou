import { isAdmin } from "../../lib/admin-auth.js";
import { json } from "../../lib/http.js";

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" });
  return json(res, 200, { authenticated: isAdmin(req) });
}
