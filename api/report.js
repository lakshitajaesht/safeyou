import { json, readJson, setCors } from "../lib/http.js";
import { submitReport } from "../lib/reputation.js";

export default async function handler(req, res) {
  setCors(res);
  if (req.method === "OPTIONS") return res.end();
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  try {
    const body = await readJson(req);
    req.safeYouContext = { url: body.url, vote: body.vote };
    const result = await submitReport(body.url, body.reporterId, body.vote);
    return json(res, 200, result);
  } catch (error) {
    const duplicate = error.message.includes("already reported");
    const clientError = duplicate || /URL|required|supported|report|private|hostname/i.test(error.message);
    return json(res, duplicate ? 409 : clientError ? 400 : 500, {
      error: clientError ? error.message : "Unable to save this report"
    });
  }
}
