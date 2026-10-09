/* CheckVault device helper: works out whether this is a phone, tablet or laptop, sets
   <html data-device="phone|tablet|laptop" data-input="touch|mouse" data-orient="portrait|landscape">
   for the pages' CSS, and asks the person only when it cannot tell. Nothing leaves the device. */
(function () {
  var KEY = "cv-device", root = document.documentElement;
  var mq = function (q) { return !!(window.matchMedia && matchMedia(q).matches); };
  var NAMES = {phone: "Phone", tablet: "Tablet", laptop: "Laptop"};

  function saved() { try { var v = localStorage.getItem(KEY); return NAMES[v] ? v : null; } catch (e) { return null; } }
  function remember(v) { try { if (v) localStorage.setItem(KEY, v); else localStorage.removeItem(KEY); } catch (e) {} }
  function byWidth() { var w = innerWidth; return w < 600 ? "phone" : w < 1000 ? "tablet" : "laptop"; }

  function guess() {
    var ua = navigator.userAgent || "", pts = navigator.maxTouchPoints || 0;
    var coarse = mq("(pointer: coarse)"), mouse = mq("(pointer: fine)") && mq("(hover: hover)");
    var short = Math.min(screen.width || 0, screen.height || 0);
    if (/iPhone|iPod/.test(ua)) return {d: "phone", sure: true};
    if (/iPad/.test(ua) || (navigator.platform === "MacIntel" && pts > 1)) return {d: "tablet", sure: true};
    if (/Android/.test(ua)) return {d: /Mobile/.test(ua) ? "phone" : "tablet", sure: true};
    if (coarse && pts > 0 && short) {            // a touch device we do not recognise: go by its screen size
      if (short < 540) return {d: "phone", sure: true};
      if (short < 640) return {d: "phone", sure: false};
      if (short < 1000) return {d: "tablet", sure: true};
      if (short < 1200) return {d: "tablet", sure: false};
      return {d: "laptop", sure: false};
    }
    if (mouse && /Windows|Macintosh|X11|CrOS|Linux/.test(ua)) return {d: "laptop", sure: true};
    return {d: byWidth(), sure: false};          // mixed or missing signals: ask
  }

  function orient() { root.setAttribute("data-orient", innerHeight >= innerWidth ? "portrait" : "landscape"); }
  function apply(d, how) {
    root.setAttribute("data-device", d);
    root.setAttribute("data-input", mq("(pointer: coarse)") ? "touch" : "mouse");
    root.setAttribute("data-how", how);
    orient();
    window.dispatchEvent(new Event("cv-device"));
  }

  function ask(fromButton) {
    if (document.getElementById("cv-ask")) return;
    if (!document.getElementById("cv-ask-css")) {
      var st = document.createElement("style"); st.id = "cv-ask-css";
      st.textContent = "#cv-ask{position:fixed;inset:0;z-index:99999;display:grid;place-items:center;padding:16px;background:rgba(12,6,30,.84);color:#fff;font:16px/1.4 system-ui,sans-serif}" +
        "#cv-ask .cv-card{width:min(380px,100%);display:grid;gap:12px;text-align:center;padding:22px;border-radius:20px;background:#241552;border:1px solid rgba(255,255,255,.2)}" +
        "#cv-ask h2{margin:0;font-size:1.3rem}#cv-ask p{margin:0;color:#cfc8ee;font-size:.92rem}" +
        "#cv-ask .cv-opts{display:grid;gap:8px}" +
        "#cv-ask button{font:inherit;font-weight:700;min-height:48px;padding:12px;border-radius:14px;cursor:pointer;border:1.5px solid #ffd166;background:rgba(255,209,102,.14);color:#ffd166}" +
        "#cv-ask .cv-alt{border-color:transparent;background:none;color:#cfc8ee;text-decoration:underline;font-weight:500}" +
        "#cv-ask button:focus-visible{outline:3px solid #fff;outline-offset:2px}";
      document.head.appendChild(st);
    }
    var box = document.createElement("div");
    box.id = "cv-ask"; box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true"); box.setAttribute("aria-labelledby", "cv-ask-t");
    box.innerHTML = '<div class="cv-card"><h2 id="cv-ask-t">' + (fromButton ? "Change the layout" : "What are you using?") + "</h2><p>" +
      (fromButton ? "Pick the screen you are on." : "I could not tell for sure, so I am asking. This only changes how the pages are laid out.") +
      '</p><div class="cv-opts"><button data-d="phone">Phone</button><button data-d="tablet">Tablet</button><button data-d="laptop">Laptop or desktop</button></div>' +
      '<button class="cv-alt" data-d="auto">' + (fromButton ? "Detect automatically" : "Not sure, pick for me") + "</button></div>";
    function close() { document.removeEventListener("keydown", esc); if (box.parentNode) box.parentNode.removeChild(box); }
    function esc(e) { if (e.key === "Escape" && fromButton) close(); }
    box.addEventListener("click", function (e) {
      var d = e.target && e.target.getAttribute && e.target.getAttribute("data-d");
      if (NAMES[d]) { remember(d); apply(d, "chosen"); close(); }
      else if (d === "auto") {
        remember(null);
        var g = guess(); apply(g.d, g.sure ? "auto" : "guess"); close();
      }
    });
    document.addEventListener("keydown", esc);
    document.body.appendChild(box);
    setTimeout(function () { var b = box.querySelector("button"); if (b) b.focus(); }, 0);
  }

  var s = saved(), g = s ? null : guess();
  apply(s || g.d, s ? "chosen" : g.sure ? "auto" : "guess");
  window.addEventListener("resize", orient);
  window.addEventListener("orientationchange", orient);
  if (!s && !g.sure) {
    if (document.body) ask(false); else document.addEventListener("DOMContentLoaded", function () { ask(false); });
  }
  window.CV = {
    device: function () { return root.getAttribute("data-device"); },
    label: function () { return NAMES[root.getAttribute("data-device")] + (root.getAttribute("data-how") === "chosen" ? "" : " (auto)"); },
    ask: function () { ask(true); },
    _guess: guess
  };
})();
