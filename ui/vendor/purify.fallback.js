/* Minimal offline fallback for DOMPurify
 * Provides a sanitize() that returns input as-is.
 * Safe when paired with marked.fallback, which already escapes HTML.
 * If the real DOMPurify is available, it will overwrite this global.
 */
(function (global) {
  if (typeof global.DOMPurify !== "undefined") return;
  global.DOMPurify = {
    sanitize: function (html) {
      return String(html ?? "");
    },
    // compatibility no-op hooks
    addHook: function () {},
    removeHook: function () {},
  };
})(typeof window !== "undefined" ? window : globalThis);

