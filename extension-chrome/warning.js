const params = new URLSearchParams(location.search);
const target = params.get("target");
const tabId = Number(params.get("tab"));
document.querySelector("#target").textContent = target || "Unknown address";

browser.runtime.sendMessage({ type: "get-state", tabId }).then((state) => {
  if (!state) return;
  const signalText = (state.signals || []).slice(0, 4)
    .map((signal) => `<li>${signal.message}</li>`).join("");
  document.querySelector("#details").innerHTML =
    `<strong>Risk score: ${state.riskScore ?? "unknown"}/100</strong>` +
    (signalText ? `<ul>${signalText}</ul>` : "");
});

document.querySelector("#back").addEventListener("click", () => {
  browser.tabs.update(tabId, { url: "chrome://newtab/" });
});

document.querySelector("#proceed").addEventListener("click", async () => {
  if (!target) return;
  await browser.runtime.sendMessage({
    type: "navigate-approved",
    tabId,
    url: target
  });
});

document.querySelector("#report-safe").addEventListener("click", async () => {
  const message = document.querySelector("#message");
  try {
    await safeYou.report(target, "safe");
    message.textContent = "Thank you. Your false-positive report was recorded.";
  } catch (error) {
    message.textContent = error.message;
  }
});

document.querySelector("#report-malicious").addEventListener("click", async () => {
  const message = document.querySelector("#message");
  try {
    await safeYou.report(target, "malicious");
    message.textContent = "Thank you. Your malicious-site report was recorded.";
  } catch (error) {
    message.textContent = error.message;
  }
});
