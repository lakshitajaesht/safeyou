import { getDb } from "./db.js";

function serialize(record) {
  return {
    id: String(record._id || record.canonicalUrl),
    url: record.canonicalUrl,
    hostname: record.hostname,
    verdict: record.verdict || "unknown",
    riskScore: record.riskScore ?? 50,
    confidence: record.confidence ?? 0,
    owner: record.owner || null,
    title: record.title || null,
    reports: record.reports || { safe: 0, malicious: 0 },
    signals: record.signals || [],
    yara: record.yara || null,
    urlscan: record.urlscan || null,
    scannedAt: record.scannedAt || null,
    updatedAt: record.updatedAt || null
  };
}

export async function listSites({ page = 1, limit = 50, search = "" } = {}) {
  const safePage = Math.max(1, Number(page) || 1);
  const safeLimit = Math.min(100, Math.max(1, Number(limit) || 50));
  const term = String(search || "").trim();
  const db = await getDb();
  const collection = db.collection("reputations");
  let records;
  let total;

  if (db.isMemory) {
    records = await collection.allDocuments();
    if (term) {
      const needle = term.toLowerCase();
      records = records.filter((record) =>
        [record.canonicalUrl, record.hostname, record.owner, record.title, record.verdict]
          .some((value) => String(value || "").toLowerCase().includes(needle)));
    }
    records.sort((a, b) =>
      new Date(b.updatedAt || b.scannedAt || 0) - new Date(a.updatedAt || a.scannedAt || 0));
    total = records.length;
    records = records.slice((safePage - 1) * safeLimit, safePage * safeLimit);
  } else {
    const escapedTerm = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const query = term ? {
      $or: [
        { canonicalUrl: { $regex: escapedTerm, $options: "i" } },
        { hostname: { $regex: escapedTerm, $options: "i" } },
        { owner: { $regex: escapedTerm, $options: "i" } },
        { title: { $regex: escapedTerm, $options: "i" } },
        { verdict: { $regex: escapedTerm, $options: "i" } }
      ]
    } : {};
    [records, total] = await Promise.all([
      collection.find(query)
        .sort({ updatedAt: -1, scannedAt: -1 })
        .skip((safePage - 1) * safeLimit)
        .limit(safeLimit)
        .toArray(),
      collection.countDocuments(query)
    ]);
  }

  return {
    sites: records.map(serialize),
    page: safePage,
    limit: safeLimit,
    total,
    pages: Math.max(1, Math.ceil(total / safeLimit))
  };
}
