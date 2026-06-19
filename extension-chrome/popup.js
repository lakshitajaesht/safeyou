let state;
const dialog = document.querySelector("#backend-dialog");
const backendInput = document.querySelector("#backend-url");
const backendResult = document.querySelector("#backend-result");

function validatedBackendUrl() {
  const url = new URL(backendInput.value.trim());
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Use an HTTP or HTTPS URL.");
  }
  return backendInput.value.trim().replace(/\/+$/, "");
}

async function testBackend() {
  const button = document.querySelector("#test-backend");
  button.disabled = true;
  backendResult.className = "connection-result";
  backendResult.textContent = "Testing connection…";

  try {
    const backendUrl = validatedBackendUrl();
    const response = await fetch(`${backendUrl}/health`);
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.ok) throw new Error("The server did not return a healthy response.");
    backendResult.className = "connection-result success";
    backendResult.textContent = `Connected · ${data.database || "backend ready"}`;
    return true;
  } catch (error) {
    backendResult.className = "connection-result failure";
    backendResult.textContent = `Connection failed: ${error.message}`;
    return false;
  } finally {
    button.disabled = false;
  }
}

async function init() {
  const actions = document.querySelector("#actions");
  actions.hidden = true;

  try {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    state = await browser.runtime.sendMessage({ type: "get-state", tabId: tab.id });
    if (!state) {
      document.querySelector("#status").textContent = "No result for this tab yet.";
      document.querySelector("#site").textContent =
        /^https?:\/\//i.test(tab.url || "") ? new URL(tab.url).hostname : "";
      return;
    }

    const status = document.querySelector("#status");
    const labels = {
      safe: "This website looks safe",
      malicious: "Potential phishing website",
      unknown: "User discretion required",
      checking: "Checking website…"
    };
    status.textContent = labels[state.verdict] || "No classification";
    status.className = `status ${state.verdict}-status`;
    document.querySelector("#site").textContent =
      state.hostname || (state.targetUrl ? new URL(state.targetUrl).hostname : "");
    document.querySelector("#meta").textContent =
      state.riskScore == null ? "" : `Risk ${state.riskScore}/100 · Confidence ${state.confidence || 0}%`;
    actions.hidden = state.verdict === "checking" || !state.targetUrl;
  } catch (error) {
    document.querySelector("#message").textContent = `Could not read this tab: ${error.message}`;
  }
}

document.querySelectorAll("[data-vote]").forEach((button) => {
  button.addEventListener("click", async () => {
    const message = document.querySelector("#message");
    if (!state?.targetUrl) {
      message.textContent = "Open a website and wait for SafeYou to check it first.";
      document.querySelector("#actions").hidden = true;
      return;
    }
    try {
      await safeYou.report(state.reportUrl || state.url || state.targetUrl, button.dataset.vote);
      message.textContent = "Report saved. Thank you.";
      document.querySelector("#actions").hidden = true;
    } catch (error) {
      message.textContent = error.message;
    }
  });
});

document.querySelector("#options").addEventListener("click", () => {
  safeYou.config().then(({ apiBaseUrl }) => {
    backendInput.value = apiBaseUrl;
    backendResult.textContent = "";
    backendResult.className = "connection-result";
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
  }).catch((error) => {
    document.querySelector("#message").textContent = error.message;
  });
});

document.querySelector("#close-dialog").addEventListener("click", () => {
  if (typeof dialog.close === "function") dialog.close();
  else dialog.removeAttribute("open");
});
document.querySelector("#test-backend").addEventListener("click", testBackend);

document.querySelector("#backend-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const apiBaseUrl = validatedBackendUrl();
    await browser.storage.local.set({ apiBaseUrl });
    backendResult.className = "connection-result success";
    backendResult.textContent = "Backend URL saved.";
    document.querySelector("#message").textContent = `Backend: ${apiBaseUrl}`;
    setTimeout(() => {
      if (typeof dialog.close === "function") dialog.close();
      else dialog.removeAttribute("open");
    }, 650);
  } catch (error) {
    backendResult.className = "connection-result failure";
    backendResult.textContent = error.message;
  }
});

init();
