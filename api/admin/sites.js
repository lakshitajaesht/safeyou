import { requireAdmin } from "../../lib/admin-auth.js";
import { listSites } from "../../lib/admin-sites.js";
import { json } from "../../lib/http.js";

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" });
  if (!requireAdmin(req, res, json)) return;

  try {
    const query = new URL(req.url, "http://localhost").searchParams;
    const result = await listSites({
      page: query.get("page"),
      limit: query.get("limit"),
      search: query.get("search")
    });
    return json(res, 200, result);
  } catch (error) {
    console.error(`[SafeYou] Admin site listing failed: ${error.message}`);
    return json(res, 500, { error: "Unable to load website records" });
  }
}
