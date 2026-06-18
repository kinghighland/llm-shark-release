/* Minimal offline fallback for marked.js
 * Provides a very small subset: paragraphs, **bold**, *italic*, inline links, and fenced code blocks.
 * Safe by design: escapes HTML by default.
 * If the real CDN marked is available, it will overwrite this global.
 */
(function (global) {
  if (typeof global.marked !== "undefined") return;
  function esc(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
  function simpleMarkdown(src) {
    const text = String(src || "");
    // fenced code blocks
    const codeRe = /```([\s\S]*?)```/g;
    let html = text.replace(codeRe, function (_, code) {
      return "<pre><code>" + esc(code) + "</code></pre>";
    });
    // inline code
    html = html.replace(/`([^`]+)`/g, function (_, code) {
      return "<code>" + esc(code) + "</code>";
    });
    // bold/italic
    html = html
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/\*([^*]+)\*/g, "<em>$1</em>");
    // links [text](url)
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, function (_m, text, url) {
      const u = esc(url);
      return '<a href="' + u + '" target="_blank" rel="noopener noreferrer">' + esc(text) + "</a>";
    });
    // paragraphs (preserve blank lines as <br>)
    const parts = html.split(/\n{2,}/).map(function (p) {
      const body = p.replace(/\n/g, "<br>");
      // if already a block element like <pre>… don't wrap
      if (/^\s*<pre[\s>]/i.test(body)) return body;
      return "<p>" + body + "</p>";
    });
    return parts.join("\n");
  }
  global.marked = {
    parse: function (src/*, opts */) {
      return simpleMarkdown(src);
    }
  };
})(typeof window !== "undefined" ? window : globalThis);

