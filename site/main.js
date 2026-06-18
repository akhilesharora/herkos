// Herkos - minimal vanilla JS. No deps, no network.
// Handles: scroll-reveal, mobile nav, docs sidebar, copy-to-clipboard.
(function () {
  "use strict";

  var reduceMotion = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---- scroll reveal ----
  function initReveal() {
    var els = document.querySelectorAll(".reveal");
    if (!els.length) return;

    if (reduceMotion || !("IntersectionObserver" in window)) {
      els.forEach(function (el) { el.classList.add("in"); });
      return;
    }

    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          e.target.classList.add("in");
          obs.unobserve(e.target);
        }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });

    els.forEach(function (el) { obs.observe(el); });
  }

  // ---- mobile header nav ----
  function initNav() {
    var toggle = document.querySelector(".nav-toggle");
    var nav = document.getElementById("primary-nav");
    if (!toggle || !nav) return;

    toggle.addEventListener("click", function () {
      var open = nav.getAttribute("data-open") === "true";
      nav.setAttribute("data-open", String(!open));
      toggle.setAttribute("aria-expanded", String(!open));
    });

    // close when a link is tapped
    nav.addEventListener("click", function (e) {
      if (e.target.closest("a")) {
        nav.setAttribute("data-open", "false");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  // ---- docs sidebar (mobile collapse) ----
  function initDocsSidebar() {
    var btn = document.querySelector(".docs-side-toggle");
    var nav = document.querySelector(".docs-side nav");
    if (!btn || !nav) return;

    btn.addEventListener("click", function () {
      var open = nav.getAttribute("data-open") === "true";
      nav.setAttribute("data-open", String(!open));
      btn.setAttribute("aria-expanded", String(!open));
    });
  }

  // ---- copy to clipboard ----
  function textOf(block) {
    // grab the command text, ignoring the leading prompt glyph and comments
    var pre = block.querySelector("pre");
    if (!pre) return "";
    var clone = pre.cloneNode(true);
    clone.querySelectorAll(".c-prompt, .c-comment").forEach(function (n) {
      n.parentNode.removeChild(n);
    });
    return clone.textContent.replace(/\n+/g, "\n").trim();
  }

  function flash(btn, label, cls) {
    var orig = btn.getAttribute("data-label") || "Copy";
    btn.classList.add(cls);
    btn.querySelector(".lbl").textContent = label;
    window.setTimeout(function () {
      btn.classList.remove(cls);
      btn.querySelector(".lbl").textContent = orig;
    }, 1600);
  }

  function initCopy() {
    document.querySelectorAll(".cmd").forEach(function (block) {
      var btn = block.querySelector(".copy-btn");
      if (!btn) return;
      btn.setAttribute("data-label", btn.querySelector(".lbl").textContent.trim());

      btn.addEventListener("click", function () {
        var text = textOf(block);
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(
            function () { flash(btn, "Copied", "copied"); },
            function () { fallbackCopy(text, btn); }
          );
        } else {
          fallbackCopy(text, btn);
        }
      });
    });
  }

  function fallbackCopy(text, btn) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "absolute";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      flash(btn, "Copied", "copied");
    } catch (err) {
      flash(btn, "Press Ctrl+C", "copied");
    }
    document.body.removeChild(ta);
  }

  // ---- year stamp ----
  function initYear() {
    document.querySelectorAll("[data-year]").forEach(function (el) {
      el.textContent = String(new Date().getFullYear());
    });
  }

  // ---- heading anchors (deep links you can copy) ----
  function initAnchors() {
    var hs = document.querySelectorAll(".docs-main h1[id], .docs-main h2[id], .docs-main h3[id]");
    hs.forEach(function (h) {
      var a = document.createElement("a");
      a.className = "heading-anchor";
      a.href = "#" + h.id;
      a.setAttribute("aria-label", "Copy link to this section");
      a.textContent = "#";
      a.addEventListener("click", function (e) {
        e.preventDefault();
        history.replaceState(null, "", "#" + h.id);
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(location.href);
        }
      });
      h.appendChild(a);
    });
  }

  function init() {
    initReveal();
    initNav();
    initDocsSidebar();
    initCopy();
    initYear();
    initAnchors();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
