import { json, readJson, setCors } from "../lib/http.js";
import { checkReputation } from "../lib/reputation.js";

export default async function handler(req, res) {
  setCors(res);
  if (req.method === "OPTIONS") return res.end();
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  try {
    const body = await readJson(req);
    req.safeYouContext = { url: body.url };
    const result = await checkReputation(body.url);
    return json(res, 200, result);
  } catch (error) {
    const clientError = /URL|required|supported|private|hostname/i.test(error.message);
    return json(res, clientError ? 400 : 500, {
      error: clientError ? error.message : "Unable to check this URL"
    });
  }
}
