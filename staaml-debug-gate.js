/**
 * StaamlCorp Debug Gate
 *
 * Wraps console.* so production builds emit nothing unless a reviewer
 * explicitly opts in via `window.__STAAML_DEBUG__ = true` in DevTools,
 * or the `?staaml_debug=1` query string, or localStorage['__STAAML_DEBUG__']='1'.
 *
 * This shim MUST be loaded BEFORE any StaamlCorp framework scripts so
 * every log/warn/error made by those scripts flows through the gate.
 *
 * Original console methods are preserved on window.__origConsole__ so a
 * debug session can restore them if needed.
 */
(function () {
  'use strict';
  if (window.__STAAML_DEBUG_GATE_INSTALLED__) return;
  window.__STAAML_DEBUG_GATE_INSTALLED__ = true;

  var qs = (typeof location !== 'undefined' && location.search) || '';
  var ls = null;
  try { ls = window.localStorage && window.localStorage.getItem('__STAAML_DEBUG__'); } catch (e) {}
  var enabled = !!window.__STAAML_DEBUG__
              || /[?&]staaml_debug=1\b/.test(qs)
              || ls === '1';

  var noop = function () {};
  var orig = {};
  ['log', 'info', 'debug', 'warn', 'error', 'trace', 'table', 'group', 'groupCollapsed', 'groupEnd']
    .forEach(function (m) {
      if (console && typeof console[m] === 'function') {
        orig[m] = console[m].bind(console);
        if (!enabled) console[m] = (m === 'error') ? orig[m] : noop;
      }
    });
  window.__origConsole__ = orig;
  window.__STAAML_DEBUG__ = enabled;
})();
