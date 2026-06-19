const params = new URLSearchParams(location.search);
const target = params.get("url");
const tabId = Number(params.get("tab"));
const errorBox = document.querySelector("#error");
const recovery = document.querySelector("#recovery");

function showError(message) {
  document.querySelector(".spinner").hidden = true;
  errorBox.hidden = false;
  errorBox.textContent = message;
  recovery.hidden = false;
}

async function continueToSite(result) {
  const stateTarget = result.finalUrl || target;
  try {
    await browser.runtime.sendMessage({
      type: "set-state",
      tabId,
      state: {
        ...result,
        targetUrl: stateTarget,
        reportUrl: result.url || target
      }
    });
  } catch {
    // Navigation is more important than retaining a popup result.
  }

  const response = await browser.runtime.sendMessage({
    type: "navigate-approved",
    tabId,
    url: target
  });
  if (response?.ok === false) throw new Error(response.error || "The page could not be opened");
}

async function run() {
  if (!target || !/^https?:\/\//i.test(target)) {
    showError("This address cannot be checked.");
    return;
  }

  document.querySelector("#host").textContent = new URL(target).hostname;
  try {
    await browser.runtime.sendMessage({
      type: "set-state",
      tabId,
      state: { verdict: "checking", targetUrl: target }
    });
  } catch {
    // Continue checking even if badge state cannot be stored.
  }

  try {
    const result = await safeYou.check(target);
    if (result.verdict === "malicious") {
      await browser.runtime.sendMessage({
        type: "set-state",
        tabId,
        state: { ...result, targetUrl: target }
      });
      await browser.runtime.sendMessage({
        type: "show-warning",
        tabId,
        url: target
      });
      return;
    }
    await continueToSite(result);
  } catch (error) {
    // Fail open so a backend outage does not make the browser unusable.
    try {
      await continueToSite({
        verdict: "unknown",
        riskScore: 50,
        confidence: 0,
        source: "backend-unavailable",
        signals: [],
        error: error.message
      });
    } catch (navigationError) {
      showError(navigationError.message);
    }
  }
}

document.querySelector("#retry").addEventListener("click", () => location.reload());
document.querySelector("#open-anyway").addEventListener("click", async () => {
  try {
    await continueToSite({
      verdict: "unknown",
      riskScore: 50,
      confidence: 0,
      source: "user-bypass",
      signals: []
    });
  } catch (error) {
    showError(error.message);
  }
});

run();
