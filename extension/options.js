const input = document.querySelector("#api");
const message = document.querySelector("#message");

browser.storage.local.get({ apiBaseUrl: "http://localhost:3000" }).then((data) => {
  input.value = data.apiBaseUrl;
});

document.querySelector("#save").addEventListener("click", async () => {
  try {
    const url = new URL(input.value);
    if (!["http:", "https:"].includes(url.protocol)) throw new Error();
    await browser.storage.local.set({ apiBaseUrl: input.value.replace(/\/+$/, "") });
    message.textContent = "Saved.";
  } catch {
    message.textContent = "Enter a valid HTTP or HTTPS URL.";
  }
});
