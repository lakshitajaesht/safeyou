browser.runtime.sendMessage({ type: "get-state" }).then((state) => {
  const currentUrl = new URL(location.href);
  currentUrl.hash = "";
  if (!state || state.targetUrl !== currentUrl.toString() || state.verdict === "malicious") return;

  const root = document.createElement("div");
  const shadow = root.attachShadow({ mode: "closed" });
  const safe = state.verdict === "safe";
  shadow.innerHTML = `
    <style>
      .notice{position:fixed;right:18px;top:18px;z-index:2147483647;width:320px;
        box-sizing:border-box;padding:14px 16px;border-radius:12px;color:#fff;
        background:${safe ? "#167d3f" : "#a96300"};font:14px/1.4 system-ui,sans-serif;
        box-shadow:0 10px 32px #0005}
      strong{font-size:15px}.row{display:flex;justify-content:space-between;gap:12px}
      button{border:0;border-radius:7px;padding:6px 9px;cursor:pointer}
      .actions{display:flex;gap:8px;margin-top:10px}.close{background:transparent;color:#fff;padding:0}
    </style>
    <aside class="notice">
      <div class="row"><strong>${safe ? "SafeYou: site looks safe" : "SafeYou: use your discretion"}</strong>
        <button class="close" aria-label="Close">✕</button></div>
      <div>${safe ? `Risk score: ${state.riskScore ?? 0}/100` :
        "There is not enough evidence to classify this page."}</div>
      <div class="actions"><button data-vote="safe">Report safe</button>
        <button data-vote="malicious">Report malicious</button></div>
    </aside>`;
  document.documentElement.appendChild(root);

  shadow.querySelector(".close").addEventListener("click", () => root.remove());
  shadow.querySelectorAll("[data-vote]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await safeYou.report(state.reportUrl || state.url || currentUrl.toString(), button.dataset.vote);
        shadow.querySelector(".actions").textContent = "Thank you. Your report was recorded.";
      } catch (error) {
        shadow.querySelector(".actions").textContent = error.message;
      }
    });
  });
  setTimeout(() => root.remove(), safe ? 6500 : 15000);
}).catch(() => {});
