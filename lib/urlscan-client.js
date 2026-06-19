const API_BASE = "https://urlscan.io/api/v1";
const USER_AGENT = "SafeYou-SecurityScanner/0.2";

function headers(json = false) {
  const result = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json"
  };
  if (json) result["Content-Type"] = "application/json";
  if (process.env.URLSCAN_API_KEY) result["API-Key"] = process.env.URLSCAN_API_KEY;
  return result;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    redirect: "follow",
    ...options,
    headers: { ...headers(Boolean(options.body)), ...(options.headers || {}) }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.message || data.description || `urlscan.io returned ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return data;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function summarize(result, source) {
  if (!result) return null;
  const overall = result.verdicts?.overall || {};
  const stats = result.stats || {};
  const requests = result.data?.requests || [];
  const secureRequests = requests.filter((entry) =>
    String(entry.request?.request?.url || entry.request?.url || "").startsWith("https:")).length;

  return {
    source,
    scanId: result.task?.uuid || result._id || null,
    resultUrl: result.task?.reportURL || result.result || null,
    malicious: Boolean(overall.malicious),
    verdictScore: Number(overall.score || 0),
    verdictCategories: overall.categories || [],
    brands: (result.brands || []).map((brand) => brand.name || brand).filter(Boolean),
    page: {
      domain: result.page?.domain || null,
      ip: result.page?.ip || null,
      country: result.page?.country || null,
      server: result.page?.server || null,
      status: result.page?.status || null,
      title: result.page?.title || null
    },
    network: {
      requests: Number(stats.requests || requests.length || 0),
      secureRequests,
      uniqueDomains: Number(stats.uniqDomains || 0),
      uniqueIPs: Number(stats.uniqIPs || 0),
      dataLength: Number(stats.dataLength || 0)
    }
  };
}

async function searchRecent(domain) {
  const query = encodeURIComponent(`page.domain:${domain} AND date:>now-7d`);
  const data = await requestJson(`${API_BASE}/search/?q=${query}&size=1`);
  return data.results?.[0] || null;
}

async function getResult(scanId) {
  return requestJson(`${API_BASE}/result/${encodeURIComponent(scanId)}/`);
}

async function submit(url) {
  return requestJson(`${API_BASE}/scan/`, {
    method: "POST",
    body: JSON.stringify({
      url,
      visibility: process.env.URLSCAN_VISIBILITY || "unlisted",
      tags: ["safeyou"]
    })
  });
}

async function waitForResult(scanId, maximumWaitMs) {
  const deadline = Date.now() + maximumWaitMs;
  await sleep(Math.min(5000, maximumWaitMs));
  while (Date.now() < deadline) {
    try {
      return await getResult(scanId);
    } catch (error) {
      if (error.status !== 404) throw error;
    }
    await sleep(2000);
  }
  return null;
}

export async function analyzeWithUrlscan({ url, domain }) {
  if (process.env.URLSCAN_ENABLED === "false") {
    return { status: "disabled", result: null };
  }

  try {
    const existing = await searchRecent(domain);
    if (existing?._id) {
      try {
        return {
          status: "complete",
          result: summarize(await getResult(existing._id), "recent-search")
        };
      } catch {
        return {
          status: "complete",
          result: summarize(existing, "recent-search")
        };
      }
    }

    const maySubmit = Boolean(process.env.URLSCAN_API_KEY) &&
      process.env.URLSCAN_SUBMIT !== "false";
    if (!maySubmit) return { status: "not-found", result: null };

    const submission = await submit(url);
    const maximumWaitMs = Math.max(0, Number(process.env.URLSCAN_WAIT_MS || 12000));
    const result = maximumWaitMs
      ? await waitForResult(submission.uuid, maximumWaitMs)
      : null;

    return result
      ? { status: "complete", result: summarize(result, "submitted") }
      : {
          status: "pending",
          result: {
            source: "submitted",
            scanId: submission.uuid,
            resultUrl: submission.result || null
          }
        };
  } catch (error) {
    return {
      status: "error",
      error: error.message,
      result: null
    };
  }
}
