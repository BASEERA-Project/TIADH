/* =========================================================================
   soc.js — the small amount of behaviour the dashboard needs.

   Everything here is progressive: the page is fully readable with JavaScript
   disabled. This file adds the theme toggle, the auto-refresh timer, the UTC
   clock, chart tooltips, copy-to-clipboard and a couple of keyboard shortcuts.

   No framework, no build step, no external request — the Content-Security-Policy
   forbids one, and a security tool that phones out to a CDN to render is telling
   on itself.
   ========================================================================= */

(function () {
  "use strict";

  var STORE = {
    theme: "tiadh.theme",
    refresh: "tiadh.refresh"
  };

  function read(key, fallback) {
    try { return window.localStorage.getItem(key) || fallback; }
    catch (e) { return fallback; }
  }

  function write(key, value) {
    try { window.localStorage.setItem(key, value); } catch (e) { /* private mode */ }
  }

  /* -- theme ------------------------------------------------------------ */

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    var button = document.querySelector("[data-theme-toggle]");
    if (button) {
      button.setAttribute("aria-label", theme === "dark" ? "Switch to light theme"
                                                         : "Switch to dark theme");
      var label = button.querySelector("[data-theme-label]");
      if (label) { label.textContent = theme === "dark" ? "Light" : "Dark"; }
    }
  }

  function initTheme() {
    applyTheme(read(STORE.theme, "dark"));
    var button = document.querySelector("[data-theme-toggle]");
    if (!button) { return; }
    button.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark"
        ? "light" : "dark";
      write(STORE.theme, next);
      applyTheme(next);
    });
  }

  /* -- clock and auto-refresh ------------------------------------------- */

  function pad(n) { return (n < 10 ? "0" : "") + n; }

  function initClock() {
    var clock = document.querySelector("[data-clock]");
    if (!clock) { return; }
    function tick() {
      var now = new Date();
      clock.textContent = now.getUTCFullYear() + "-" + pad(now.getUTCMonth() + 1) + "-" +
        pad(now.getUTCDate()) + " " + pad(now.getUTCHours()) + ":" +
        pad(now.getUTCMinutes()) + ":" + pad(now.getUTCSeconds()) + "Z";
    }
    tick();
    window.setInterval(tick, 1000);
  }

  function initRefresh() {
    var select = document.querySelector("[data-refresh]");
    if (!select) { return; }

    var stored = read(STORE.refresh, select.getAttribute("data-default") || "0");
    if (select.querySelector('option[value="' + stored + '"]')) { select.value = stored; }

    var timer = null;
    function schedule() {
      if (timer) { window.clearTimeout(timer); timer = null; }
      var seconds = parseInt(select.value, 10);
      if (!seconds) { return; }
      timer = window.setTimeout(function () { window.location.reload(); }, seconds * 1000);
    }

    select.addEventListener("change", function () {
      write(STORE.refresh, select.value);
      schedule();
    });

    // A refresh mid-interaction is worse than a stale page: hold it while the
    // tab is hidden or the analyst is typing in a filter.
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        if (timer) { window.clearTimeout(timer); timer = null; }
      } else {
        schedule();
      }
    });
    document.addEventListener("focusin", function (event) {
      if (event.target.matches("input, select, textarea") && timer) {
        window.clearTimeout(timer);
        timer = null;
      }
    });

    schedule();
  }

  /* -- tooltips --------------------------------------------------------- */

  function initTooltips() {
    var tip = null;

    function show(target) {
      var text = target.getAttribute("data-tip");
      if (!text) { return; }
      if (!tip) {
        tip = document.createElement("div");
        tip.className = "tip";
        document.body.appendChild(tip);
      }
      tip.textContent = text;
      var box = target.getBoundingClientRect();
      tip.classList.add("is-visible");
      var width = tip.offsetWidth;
      var left = Math.min(
        Math.max(6, box.left + box.width / 2 - width / 2),
        window.innerWidth - width - 6
      );
      var top = box.top - tip.offsetHeight - 8;
      tip.style.left = left + "px";
      tip.style.top = (top < 6 ? box.bottom + 8 : top) + "px";
    }

    function hide() { if (tip) { tip.classList.remove("is-visible"); } }

    document.addEventListener("mouseover", function (event) {
      var target = event.target.closest("[data-tip]");
      if (target) { show(target); }
    });
    document.addEventListener("mouseout", function (event) {
      if (event.target.closest("[data-tip]")) { hide(); }
    });
    document.addEventListener("focusin", function (event) {
      var target = event.target.closest("[data-tip]");
      if (target) { show(target); }
    });
    document.addEventListener("focusout", hide);
    window.addEventListener("scroll", hide, true);
  }

  /* -- copy ------------------------------------------------------------- */

  function initCopy() {
    document.addEventListener("click", function (event) {
      var button = event.target.closest("[data-copy]");
      if (!button) { return; }
      event.preventDefault();
      var value = button.getAttribute("data-copy");
      var done = function () {
        var previous = button.getAttribute("data-tip");
        button.setAttribute("data-tip", "copied");
        window.setTimeout(function () {
          button.setAttribute("data-tip", previous || "copy");
        }, 1200);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).then(done, function () { /* denied */ });
      }
    });
  }

  /* -- filters ---------------------------------------------------------- */

  function initFilters() {
    // Selects submit their form immediately: one interaction, not two.
    document.querySelectorAll("form[data-autosubmit] select").forEach(function (select) {
      select.addEventListener("change", function () { select.form.submit(); });
    });
    document.querySelectorAll("form[data-autosubmit] input[type=checkbox]")
      .forEach(function (box) {
        box.addEventListener("change", function () { box.form.submit(); });
      });

    document.addEventListener("keydown", function (event) {
      if (event.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName)) {
        var search = document.querySelector("[data-search]");
        if (search) { event.preventDefault(); search.focus(); search.select(); }
      }
      if (event.key === "Escape" && document.activeElement &&
          document.activeElement.matches("[data-search]")) {
        document.activeElement.blur();
      }
    });
  }

  /* -- live counters ---------------------------------------------------- */

  function initLive() {
    var strip = document.querySelector("[data-live]");
    if (!strip) { return; }
    var stamp = document.querySelector("[data-live-stamp]");

    function poll() {
      fetch("/api/summary", { headers: { Accept: "application/json" } })
        .then(function (response) {
          if (!response.ok) { throw new Error("summary unavailable"); }
          return response.json();
        })
        .then(function (data) {
          document.querySelectorAll("[data-stat]").forEach(function (node) {
            var key = node.getAttribute("data-stat");
            var value = data.stats[key];
            if (value === undefined || value === null) { return; }
            node.textContent = typeof value === "number"
              ? value.toLocaleString("en-US") : String(value);
          });
          if (stamp) { stamp.classList.remove("is-stale"); }
        })
        .catch(function () { if (stamp) { stamp.classList.add("is-stale"); } });
    }

    window.setInterval(poll, 15000);
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    initClock();
    initRefresh();
    initTooltips();
    initCopy();
    initFilters();
    initLive();
  });

  // Apply the stored theme before first paint where possible.
  applyTheme(read(STORE.theme, "dark"));
})();
