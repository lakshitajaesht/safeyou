const safeYou = {
  async config() {
    const stored = await browser.storage.local.get({
      apiBaseUrl: "http://localhost:3000"
    });
    return { apiBaseUrl: stored.apiBaseUrl.replace(/\/+$/, "") };
  },

  async reporterId() {
    const stored = await browser.storage.local.get("reporterId");
    if (stored.reporterId) return stored.reporterId;
    const reporterId = crypto.randomUUID();
    await browser.storage.local.set({ reporterId });
    return reporterId;
  },

  async check(url) {
    const { apiBaseUrl } = await this.config();
    const response = await fetch(`${apiBaseUrl}/api/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "The reputation server is unavailable");
    return data;
  },

  async report(url, vote) {
    const { apiBaseUrl } = await this.config();
    const reporterId = await this.reporterId();
    const response = await fetch(`${apiBaseUrl}/api/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, vote, reporterId })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Could not send the report");
    return data;
  }
};
