import "dotenv/config";
import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import checkHandler from "../api/check.js";
import reportHandler from "../api/report.js";
import healthHandler from "../api/health.js";
import adminLoginHandler from "../api/admin/login.js";
import adminLogoutHandler from "../api/admin/logout.js";
import adminSessionHandler from "../api/admin/session.js";
import adminSitesHandler from "../api/admin/sites.js";

const publicDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../public"
);

const routes = new Map([
  ["/api/check", checkHandler],
  ["/api/report", reportHandler],
  ["/api/health", healthHandler],
  ["/api/admin/login", adminLoginHandler],
  ["/api/admin/logout", adminLogoutHandler],
  ["/api/admin/session", adminSessionHandler],
  ["/api/admin/sites", adminSitesHandler],
  ["/health", healthHandler]
]);

const publicFiles = new Map([
  ["/", { file: "index.html", type: "text/html; charset=utf-8" }],
  ["/admin", { file: "index.html", type: "text/html; charset=utf-8" }],
  ["/admin.css", { file: "admin.css", type: "text/css; charset=utf-8" }],
  ["/admin.js", { file: "admin.js", type: "text/javascript; charset=utf-8" }]
]);

const server = http.createServer(async (req, res) => {
  const startedAt = Date.now();
  const pathname = new URL(req.url, "http://localhost").pathname;
  const handler = routes.get(pathname);
  const publicFile = publicFiles.get(pathname);

  res.on("finish", () => {
    const response = res.safeYouResponse || {};
    const context = req.safeYouContext || {};
    const details = [
      context.url && `url=${context.url}`,
      context.vote && `vote=${context.vote}`,
      response.verdict && `verdict=${response.verdict}`,
      response.riskScore != null && `risk=${response.riskScore}/100`,
      response.database && `database=${response.database}`,
      response.error && `error=${response.error}`
    ].filter(Boolean).join(" ");

    console.log(
      `[${new Date().toISOString()}] ${req.method} ${pathname} -> ` +
      `${res.statusCode} (${Date.now() - startedAt}ms)` +
      (details ? ` | ${details}` : "")
    );
  });

  if (publicFile && req.method === "GET") {
    try {
      const contents = await readFile(path.join(publicDirectory, publicFile.file));
      res.statusCode = 200;
      res.setHeader("Content-Type", publicFile.type);
      res.setHeader("Cache-Control", publicFile.file === "index.html" ? "no-store" : "public, max-age=300");
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-Frame-Options", "DENY");
      res.setHeader("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'");
      return res.end(contents);
    } catch {
      res.statusCode = 500;
      return res.end("Unable to load admin dashboard");
    }
  }

  if (!handler) {
    res.statusCode = 404;
    return res.end("Not found");
  }

  try {
    await handler(req, res);
  } catch (error) {
    console.error(`[SafeYou] Unhandled request error: ${error.message}`);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  }
});

const port = Number(process.env.PORT || 3000);
server.listen(port, () => {
  console.log(`SafeYou API listening at http://localhost:${port}`);
  console.log(`Database mode: ${process.env.MONGODB_URI ? "MongoDB" : "in-memory development"}`);
  console.log(`Admin dashboard: http://localhost:${port}/admin`);
  console.log(`Admin login: ${process.env.ADMIN_PASSWORD && process.env.ADMIN_SESSION_SECRET ? "configured" : "not configured"}`);
  console.log("Request logs are enabled.");
});
