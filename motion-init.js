/* ==========================================================================
   Custos — Motion layer
   Built on Motion One (vendored at vendor/motion.min.js, UMD -> window.Motion).

   Everything here is purely decorative. If the library is missing, blocked, or
   the visitor prefers reduced motion, we bail out early and the page stays
   fully functional with its static CSS appearance.
   ========================================================================== */
(function () {
  "use strict";

  var M = window.Motion;
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (!M || reduced) {
    // Make sure nothing is left invisible if we never get to animate it.
    document.documentElement.classList.remove("motion-ready");
    return;
  }

  var animate = M.animate;
  var inView = M.inView;
  var stagger = M.stagger;
  var scroll = M.scroll;

  var EASE = [0.22, 1, 0.36, 1];

  function $(sel, root) {
    return (root || document).querySelector(sel);
  }
  function $$(sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  }

  /* --- Scroll progress bar ------------------------------------------------- */
  function initScrollProgress() {
    var bar = $("#scroll-progress");
    if (!bar) return;
    scroll(animate(bar, { scaleX: [0, 1] }, { ease: "linear" }));
  }

  /* --- Header elevation on scroll ------------------------------------------ */
  function initHeaderState() {
    var header = $("#site-header");
    if (!header) return;
    var ticking = false;

    function update() {
      header.classList.toggle("scrolled", window.scrollY > 8);
      ticking = false;
    }

    window.addEventListener(
      "scroll",
      function () {
        if (!ticking) {
          ticking = true;
          requestAnimationFrame(update);
        }
      },
      { passive: true }
    );
    update();
  }

  /* --- Hero intro ----------------------------------------------------------
     The ASCII wordmark rows drop in one after another, then the copy and the
     stat cards follow. Rows are cleared of their hidden state as they land.  */
  function initHeroIntro() {
    var rows = $$(".ascii-wordmark .row");
    if (rows.length) {
      animate(
        rows,
        { opacity: [0, 1], y: [-14, 0], scaleY: [0.6, 1] },
        { duration: 0.55, delay: stagger(0.07), ease: EASE }
      );
    }

    var heroBits = $$(".hero .eyebrow, .hero h1, .hero-lead");
    if (heroBits.length) {
      animate(
        heroBits,
        { opacity: [0, 1], y: [18, 0] },
        { duration: 0.6, delay: stagger(0.08, { startDelay: 0.25 }), ease: EASE }
      );
    }

    var cards = $$(".hero .stat-card");
    if (cards.length) {
      animate(
        cards,
        { opacity: [0, 1], y: [22, 0], scale: [0.97, 1] },
        { duration: 0.55, delay: stagger(0.06, { startDelay: 0.5 }), ease: EASE }
      );
    }
  }

  /* --- Generic scroll reveals ---------------------------------------------
     Any .reveal outside the hero fades up the first time it reaches the
     lower third of the viewport.

     This deliberately does NOT use inView/IntersectionObserver: the nav is
     made entirely of hash anchors, and an instant jump moves a section from
     "below the viewport" to "above the viewport" within a single frame, so
     it never produces an intersection event and the content would stay
     invisible forever. A positional test also catches anything already
     scrolled past (rect.top < 0), so nothing can be stranded.             */
  function initReveals() {
    var pending = $$(".reveal").filter(function (el) {
      return !el.closest(".hero");
    });
    if (!pending.length) return;

    function flush() {
      var vh = window.innerHeight || document.documentElement.clientHeight;
      var batch = [];

      for (var i = pending.length - 1; i >= 0; i--) {
        if (pending[i].getBoundingClientRect().top < vh * 0.92) {
          batch.push(pending[i]);
          pending.splice(i, 1);
        }
      }

      if (batch.length) {
        batch.reverse(); // restore document order so the cascade reads top-down
        animate(
          batch,
          { opacity: [0, 1], y: [18, 0] },
          { duration: 0.6, delay: stagger(0.07), ease: EASE }
        );
      }

      if (!pending.length) {
        window.removeEventListener("scroll", onScroll);
        window.removeEventListener("resize", onScroll);
      }
    }

    var ticking = false;
    function onScroll() {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(function () {
        ticking = false;
        flush();
      });
    }

    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    flush();
  }

  /* --- Scroll-spy for the nav underline ------------------------------------ */
  function initScrollSpy() {
    var links = $$(".nav-links a[href^='#']");
    if (!links.length) return;

    links.forEach(function (link) {
      var section = document.querySelector(link.getAttribute("href"));
      if (!section) return;
      inView(
        section,
        function () {
          links.forEach(function (l) {
            l.classList.toggle("active", l === link);
          });
          return function () {
            link.classList.remove("active");
          };
        },
        { amount: 0.25 }
      );
    });
  }

  /* --- Wire inspector ------------------------------------------------------ */
  function initInspectorMotion() {
    document.addEventListener("custos:payloadrendered", function () {
      var segs = $$("#hex-stream .hex-segment");
      if (!segs.length) return;
      animate(
        segs,
        { opacity: [0, 1], y: [10, 0], scale: [0.92, 1] },
        { duration: 0.35, delay: stagger(0.025), ease: EASE }
      );
    });

    document.addEventListener("custos:segmentrendered", function () {
      var box = $("#segment-detail");
      if (!box) return;
      animate(
        box,
        { opacity: [0.4, 1], x: [-8, 0] },
        { duration: 0.3, ease: EASE }
      );
    });
  }

  /* --- Topology diagram ---------------------------------------------------- */
  function initTopologyMotion() {
    document.addEventListener("custos:topologyrendered", function () {
      var nodes = $$("#topo-flow > *");
      if (nodes.length) {
        animate(
          nodes,
          { opacity: [0, 1], x: [-18, 0] },
          { duration: 0.42, delay: stagger(0.06), ease: EASE }
        );
      }

      var specs = $$("#topo-specs .verdict-cell");
      if (specs.length) {
        animate(
          specs,
          { opacity: [0, 1], y: [10, 0] },
          { duration: 0.35, delay: stagger(0.03), ease: EASE }
        );
      }
    });
  }

  /* --- Dashboard charts ----------------------------------------------------
     Latency polylines draw themselves in via stroke-dashoffset; goodput bars
     grow from their baseline. Re-runs on every re-render (filter, import,
     theme switch), which keeps the charts feeling live.                     */
  function animateCharts() {
    $$("#latency-svg polyline").forEach(function (line, i) {
      var len;
      try {
        len = line.getTotalLength();
      } catch (e) {
        return;
      }
      if (!len) return;
      line.style.strokeDasharray = len;
      animate(
        line,
        { strokeDashoffset: [len, 0] },
        { duration: 1.1, delay: i * 0.12, ease: EASE }
      ).finished.then(function () {
        line.style.strokeDasharray = "";
      });
    });

    var dots = $$("#latency-svg circle");
    if (dots.length) {
      animate(dots, { opacity: [0, 1] }, { duration: 0.3, delay: stagger(0.012, { startDelay: 0.35 }) });
    }

    var bars = $$("#throughput-svg rect");
    if (bars.length) {
      animate(
        bars,
        { scaleY: [0, 1], opacity: [0.3, 1] },
        { duration: 0.6, delay: stagger(0.07), ease: EASE }
      );
    }

    var rows = $$("#trials-tbody tr");
    if (rows.length) {
      animate(
        rows,
        { opacity: [0, 1], y: [8, 0] },
        { duration: 0.35, delay: stagger(0.04), ease: EASE }
      );
    }
  }

  function initDashboardMotion() {
    var chartsSeen = false;
    var telemetry = $("#telemetry");

    document.addEventListener("custos:dashboardrendered", function () {
      // Don't animate the very first render until the charts are on screen.
      if (chartsSeen) animateCharts();
    });

    if (!telemetry) {
      chartsSeen = true;
      animateCharts();
      return;
    }

    // Same positional approach as initReveals, for the same anchor-jump reason.
    var ticking = false;
    function check() {
      if (chartsSeen) return;
      var vh = window.innerHeight || document.documentElement.clientHeight;
      if (telemetry.getBoundingClientRect().top < vh * 0.9) {
        chartsSeen = true;
        animateCharts();
        window.removeEventListener("scroll", onScroll);
        window.removeEventListener("resize", onScroll);
      }
    }
    function onScroll() {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(function () {
        ticking = false;
        check();
      });
    }

    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    check();
  }

  /* --- Theme switch flourish ----------------------------------------------- */
  function initThemeMotion() {
    document.addEventListener("custos:themechange", function () {
      animate(
        document.body,
        { opacity: [0.75, 1] },
        { duration: 0.35, ease: EASE }
      );

      var rows = $$(".ascii-wordmark .row");
      if (rows.length) {
        animate(
          rows,
          { y: [-6, 0], opacity: [0.5, 1] },
          { duration: 0.4, delay: stagger(0.04), ease: EASE }
        );
      }
    });
  }

  /* --- Boot ----------------------------------------------------------------
     app.js registers its own DOMContentLoaded handler before this file's, so
     by the time we run the initial inspector/topology/dashboard markup and
     their events have already been emitted. We therefore prime the listeners
     first, then replay the intro animations against the existing DOM.      */
  function boot() {
    // Signals the <head> safety net that the motion layer came up fine.
    document.documentElement.dataset.motionBooted = "1";

    initScrollProgress();
    initHeaderState();
    initInspectorMotion();
    initTopologyMotion();
    initDashboardMotion();
    initThemeMotion();
    initScrollSpy();
    initReveals();
    initHeroIntro();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
