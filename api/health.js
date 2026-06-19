import { json } from "../lib/http.js";
import { getDb } from "../lib/db.js";

export default async function handler(_req, res) {
  const db = await getDb();
  return json(res, 200, {
    ok: true,
    service: "safeyou-api",
    database: db.isMemory ? "memory-development" : "mongodb"
  });
}
