/* Small integration layer kept separate from the prebuilt Web Vault bundle. */
(() => {
  let checking = false;
  async function checkSendAccess() {
    if (checking || !/^#\/send\//.test(location.hash)) return;
    checking = true;
    try {
      const response = await fetch("/api/send-verify/status", { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) return;
      const status = await response.json();
      if (status.enabled && !status.valid) {
        // The complete Send URL (including its encryption key) stays in the
        // fragment and is never sent to the Worker as a return query string.
        location.replace("/send-verify#" + encodeURIComponent(location.pathname + location.search + location.hash));
      }
    } catch { /* Leave ordinary client error handling in control when offline. */ }
    finally { checking = false; }
  }
  window.addEventListener("hashchange", checkSendAccess);
  checkSendAccess();
})();
