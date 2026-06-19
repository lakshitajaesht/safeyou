const api = globalThis.browser;
const checkingPage = api.runtime.getURL("checking.html");
const warningPage = api.runtime.getURL("warning.html");
const approvedTabs = new Map();
const tabState = new Map();
let backendOrigin = "http://localhost:3000";

function updateBackendOrigin(value) {
  try {
    backendOrigin = new URL(value || "http://localhost:3000").origin;
  } catch {
    backendOrigin = "http://localhost:3000";
  }
}

api.storage.local.get({ apiBaseUrl: "http://localhost:3000" })
  .then(({ apiBaseUrl }) => updateBackendOrigin(apiBaseUrl));

api.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.apiBaseUrl) {
    updateBackendOrigin(changes.apiBaseUrl.newValue);
  }
});

function approveTab(tabId, durationMs = 15_000) {
  approvedTabs.set(tabId, Date.now() + durationMs);
}

function isTabApproved(tabId) {
  const expiresAt = approvedTabs.get(tabId);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    approvedTabs.delete(tabId);
    return false;
  }
  return true;
}

function isHttpUrl(url) {
  return /^https?:\/\//i.test(url);
}

function setBadge(tabId, verdict) {
  const config = {
    safe: { text: "✓", color: "#159947" },
    malicious: { text: "!", color: "#d92d20" },
    unknown: { text: "?", color: "#d9930d" },
    checking: { text: "…", color: "#57606a" }
  }[verdict] || { text: "", color: "#57606a" };
  api.action.setBadgeText({ tabId, text: config.text });
  api.action.setBadgeBackgroundColor({ tabId, color: config.color });
}

api.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !isHttpUrl(details.url)) return;

  try {
    if (new URL(details.url).origin === backendOrigin) return;
  } catch {
    return;
  }

  // Keep the tab approved throughout duplicate events and redirect chains,
  // such as google.com redirecting to www.google.com.
  if (isTabApproved(details.tabId)) return;

  const currentState = tabState.get(details.tabId);
  if (currentState?.verdict === "checking" && currentState.targetUrl === details.url) return;

  tabState.set(details.tabId, {
    verdict: "checking",
    targetUrl: details.url,
    updatedAt: Date.now()
  });
  setBadge(details.tabId, "checking");

  const redirectUrl = `${checkingPage}?tab=${details.tabId}&url=${encodeURIComponent(details.url)}`;
  try {
    await api.tabs.update(details.tabId, { url: redirectUrl });
  } catch (error) {
    console.error(`SafeYou could not open its checking page: ${error.message}`);
  }
});

api.runtime.onMessage.addListener(async (message, sender) => {
  const requestedTabId = Number(message.tabId);
  const tabId = Number.isInteger(requestedTabId) && requestedTabId >= 0
    ? requestedTabId
    : sender.tab?.id;

  if (message.type === "set-state") {
    if (!Number.isInteger(tabId)) return { ok: false, error: "No browser tab is available" };
    tabState.set(tabId, { ...message.state, updatedAt: Date.now() });
    setBadge(tabId, message.state.verdict);
    return { ok: true };
  }

  if (message.type === "get-state") {
    return tabState.get(tabId) || null;
  }

  if (message.type === "navigate-approved") {
    if (!Number.isInteger(tabId) || !isHttpUrl(message.url)) {
      return { ok: false, error: "The destination could not be opened" };
    }
    approveTab(tabId);
    await api.tabs.update(tabId, { url: message.url });
    return { ok: true };
  }

  if (message.type === "show-warning") {
    if (!Number.isInteger(tabId)) return { ok: false, error: "No browser tab is available" };
    const url = `${warningPage}?tab=${tabId}&target=${encodeURIComponent(message.url)}`;
    await api.tabs.update(tabId, { url });
    return { ok: true };
  }
});

api.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0 || !isTabApproved(details.tabId)) return;
  const state = tabState.get(details.tabId);
  if (state && isHttpUrl(details.url)) {
    tabState.set(details.tabId, {
      ...state,
      targetUrl: details.url,
      finalUrl: details.url,
      updatedAt: Date.now()
    });
  }
  setTimeout(() => approvedTabs.delete(details.tabId), 1500);
});

api.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
  approvedTabs.delete(tabId);
});

setInterval(() => {
  const now = Date.now();
  for (const [tabId, expiresAt] of approvedTabs) {
    if (expiresAt <= now) approvedTabs.delete(tabId);
  }
}, 30_000);
