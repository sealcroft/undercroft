// Render ```mermaid fences in the book: mdBook emits them as
// <pre><code class="language-mermaid">…</code></pre>; convert each to a
// <pre class="mermaid"> and hand the page to the vendored mermaid.min.js.
// Theme follows the active mdBook theme (dark themes get mermaid "dark").
(function () {
  function activeIsDark() {
    var cls = document.documentElement.className || "";
    return /ayu|navy|coal/.test(cls);
  }
  function render() {
    if (typeof mermaid === "undefined") return;
    var blocks = document.querySelectorAll("code.language-mermaid");
    blocks.forEach(function (code) {
      var pre = document.createElement("pre");
      pre.className = "mermaid";
      pre.textContent = code.textContent;
      var host = code.closest("pre") || code;
      host.parentNode.replaceChild(pre, host);
    });
    mermaid.initialize({
      startOnLoad: false,
      theme: activeIsDark() ? "dark" : "default",
      securityLevel: "strict",
    });
    mermaid.run({ querySelector: ".mermaid" });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", render);
  } else {
    render();
  }
})();
