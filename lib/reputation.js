import { getDb } from "./db.js";
import { normalizeUrl } from "./url.js";
import { publicReputation, scanUrl } from "./scanner.js";

const CACHE_AGE_MS = 24 * 60 * 60 * 1000;

export async function checkReputation(input) {
  const normalized = normalizeUrl(input);
  const db = await getDb();
  const collection = db.collection("reputations");
  const existing = await collection.findOne({ canonicalUrl: normalized.canonicalUrl });

  if (existing && existing.scannedAt &&
      Date.now() - new Date(existing.scannedAt).getTime() < CACHE_AGE_MS) {
    return publicReputation(existing);
  }

  console.log(`[SafeYou scanner] Loading and analyzing ${normalized.canonicalUrl}`);
  const scan = await scanUrl(normalized.canonicalUrl);
  const reports = existing?.reports || { safe: 0, malicious: 0 };
  const updated = {
    ...scan,
    reports,
    createdAt: existing?.createdAt || new Date(),
    updatedAt: new Date()
  };

  await collection.updateOne(
    { canonicalUrl: normalized.canonicalUrl },
    { $set: updated },
    { upsert: true }
  );
  console.log(
    `[SafeYou scanner] Analysis complete: ${scan.verdict}, ` +
    `risk ${scan.riskScore}/100, ${scan.signals.length} signal(s)`
  );
  return publicReputation(updated, existing ? "rescanned" : "analysis");
}

export async function submitReport(input, reporterId, vote) {
  if (!["safe", "malicious"].includes(vote)) throw new Error("Invalid report value");
  if (typeof reporterId !== "string" || reporterId.length < 8 || reporterId.length > 128) {
    throw new Error("A valid reporter ID is required");
  }

  const normalized = normalizeUrl(input);
  const db = await getDb();
  try {
    await db.collection("reports").insertOne({
      canonicalUrl: normalized.canonicalUrl,
      hostname: normalized.hostname,
      reporterId,
      vote,
      createdAt: new Date()
    });
  } catch (error) {
    if (error?.code === 11000) throw new Error("This browser has already reported this URL");
    throw error;
  }

  const field = `reports.${vote}`;
  await db.collection("reputations").updateOne(
    { canonicalUrl: normalized.canonicalUrl },
    {
      $setOnInsert: {
        canonicalUrl: normalized.canonicalUrl,
        hostname: normalized.hostname,
        registrableDomain: normalized.registrableDomain,
        verdict: "unknown",
        riskScore: 50,
        confidence: 0,
        createdAt: new Date()
      },
      $inc: { [field]: 1 },
      $set: { updatedAt: new Date() }
    },
    { upsert: true }
  );

  const record = await db.collection("reputations").findOne({
    canonicalUrl: normalized.canonicalUrl
  });
  return publicReputation(record, "community-report");
}
