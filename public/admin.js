const loginView = document.querySelector("#login-view");
const dashboardView = document.querySelector("#dashboard-view");
const loginError = document.querySelector("#login-error");
const table = document.querySelector("#sites-table");
const body = document.querySelector("#sites-body");
const loading = document.querySelector("#loading");
const empty = document.querySelector("#empty");
let currentPage = 1;
let totalPages = 1;
let currentSearch = "";

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || "Request failed");
    error.status = response.status;
    throw error;
  }
  return data;
}

function showLogin(message = "") {
  dashboardView.hidden = true;
  loginView.hidden = false;
  loginError.textContent = message;
  document.querySelector("#password").focus();
}

function showDashboard() {
  loginView.hidden = true;
  dashboardView.hidden = false;
}

function escapeText(value) {
  return String(value ?? "");
}

function dateLabel(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function renderSites(data) {
  loading.hidden = true;
  currentPage = data.page;
  totalPages = data.pages;
  document.querySelector("#summary").textContent =
    `${data.total} website${data.total === 1 ? "" : "s"} in the reputation database`;
  document.querySelector("#page-label").textContent = `Page ${data.page} of ${data.pages}`;
  document.querySelector("#previous").disabled = data.page <= 1;
  document.querySelector("#next").disabled = data.page >= data.pages;

  body.replaceChildren();
  table.hidden = data.sites.length === 0;
  empty.hidden = data.sites.length !== 0;

  for (const site of data.sites) {
    const row = document.createElement("tr");
    const reports = site.reports || {};
    const values = [
      { type: "site", value: site },
      { type: "verdict", value: site.verdict },
      { value: `${site.riskScore}/100` },
      { value: `${site.confidence}%` },
      { value: `Safe ${reports.safe || 0} · Bad ${reports.malicious || 0}` },
      { value: dateLabel(site.scannedAt || site.updatedAt) }
    ];

    for (const item of values) {
      const cell = document.createElement("td");
      if (item.type === "site") {
        const link = document.createElement("a");
        link.href = item.value.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = escapeText(item.value.title || item.value.hostname || item.value.url);
        const url = document.createElement("small");
        url.textContent = escapeText(item.value.url);
        cell.append(link, url);
      } else if (item.type === "verdict") {
        const badge = document.createElement("span");
        badge.className = `badge ${item.value}`;
        badge.textContent = escapeText(item.value);
        cell.appendChild(badge);
      } else {
        cell.textContent = escapeText(item.value);
      }
      row.appendChild(cell);
    }
    body.appendChild(row);
  }
}

async function loadSites(page = 1) {
  loading.hidden = false;
  loading.textContent = "Loading…";
  table.hidden = true;
  empty.hidden = true;

  try {
    const query = new URLSearchParams({
      page: String(page),
      limit: "50",
      search: currentSearch
    });
    renderSites(await api(`/api/admin/sites?${query}`));
  } catch (error) {
    if (error.status === 401) return showLogin("Your session expired. Please sign in again.");
    loading.textContent = error.message;
  }
}

document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  loginError.textContent = "";
  const button = event.currentTarget.querySelector("button");
  button.disabled = true;
  try {
    await api("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({ password: document.querySelector("#password").value })
    });
    event.currentTarget.reset();
    showDashboard();
    await loadSites(1);
  } catch (error) {
    loginError.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#logout").addEventListener("click", async () => {
  await api("/api/admin/logout", { method: "POST", body: "{}" }).catch(() => {});
  showLogin();
});

document.querySelector("#search-form").addEventListener("submit", (event) => {
  event.preventDefault();
  currentSearch = document.querySelector("#search").value.trim();
  loadSites(1);
});

document.querySelector("#previous").addEventListener("click", () => {
  if (currentPage > 1) loadSites(currentPage - 1);
});
document.querySelector("#next").addEventListener("click", () => {
  if (currentPage < totalPages) loadSites(currentPage + 1);
});

api("/api/admin/session").then((session) => {
  if (session.authenticated) {
    showDashboard();
    loadSites(1);
  } else {
    showLogin();
  }
}).catch(() => showLogin("Could not connect to the SafeYou server."));
