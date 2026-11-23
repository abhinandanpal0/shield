(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  var text = $('#text');
  var count = $('#char-count');
  function updateCount() { if (text && count) count.textContent = text.value.length.toLocaleString(); }
  if (text) { text.addEventListener('input', updateCount); updateCount(); }

  var sample = $('#load-sample');
  if (sample && text) {
    sample.addEventListener('click', function () {
      text.value = sample.getAttribute('data-sample');
      updateCount(); text.focus();
    });
  }
  var clear = $('#clear-text');
  if (clear && text) {
    clear.addEventListener('click', function () {
      text.value = ''; updateCount(); text.focus();
      var file = $('#file'); if (file) { file.value = ''; fileLabel(); }
    });
  }

  var file = $('#file'), fileName = $('#file-name');
  function fileLabel() {
    if (!fileName) return;
    fileName.textContent = file && file.files && file.files[0] ? 'This file replaces the text above.' : '';
  }
  if (file) file.addEventListener('change', fileLabel);

  // detector selection
  var typeSummary = $('.types summary .muted');
  var boxes = $$('input[name="detectors"]');
  function updateTypes() {
    if (!typeSummary) return;
    var n = boxes.filter(function (b) { return b.checked; }).length;
    typeSummary.textContent = '(' + n + ' of ' + boxes.length + ' selected)';
  }
  boxes.forEach(function (b) { b.addEventListener('change', updateTypes); });
  $$('[data-toggle-all]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var on = btn.getAttribute('data-toggle-all') === '1';
      boxes.forEach(function (b) { b.checked = on; });
      updateTypes();
    });
  });

  // prevent double submit and show progress
  var form = $('#scan-form'), scanBtn = $('#scan-btn');
  if (form && scanBtn) {
    form.addEventListener('submit', function () {
      setTimeout(function () { scanBtn.disabled = true; scanBtn.textContent = 'Scanning…'; }, 0);
    });
  }

  // results
  var results = $('#results');
  if (results) {
    results.scrollIntoView({ block: 'start' });
    results.focus({ preventScroll: true });
  }

  var tabO = $('#tab-original'), tabR = $('#tab-redacted');
  var viewO = $('#view-original'), viewR = $('#view-redacted');
  function showView(which) {
    var o = which === 'original';
    tabO.setAttribute('aria-selected', o); tabR.setAttribute('aria-selected', !o);
    viewO.hidden = !o; viewR.hidden = o;
  }
  if (tabO && tabR && viewO && viewR) {
    tabO.addEventListener('click', function () { showView('original'); });
    tabR.addEventListener('click', function () { showView('redacted'); });
    [tabO, tabR].forEach(function (t) {
      t.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
          var next = t === tabO ? tabR : tabO; next.focus(); next.click();
        }
      });
    });
    showView('original');
  }

  var status = $('#copy-status');
  function say(msg) {
    if (!status) return;
    status.textContent = msg;
    setTimeout(function () { status.textContent = ''; }, 2500);
  }
  function redactedText() { var el = $('#redacted-out'); return el ? el.textContent : ''; }

  var copy = $('#copy-btn');
  if (copy) {
    copy.addEventListener('click', function () {
      var value = redactedText();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).then(function () { say('Copied the redacted text.'); },
          function () { say('Copy was blocked. Select the text in the Redacted tab and copy it.'); });
      } else { say('Copy is not available here. Select the text in the Redacted tab and copy it.'); }
    });
  }
  var download = $('#download-btn');
  if (download) {
    download.addEventListener('click', function () {
      var blob = new Blob([redactedText()], { type: 'text/plain;charset=utf-8' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'redacted.txt';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
      say('Downloaded redacted.txt.');
    });
  }

  var reveal = $('#reveal-btn');
  if (reveal) {
    reveal.addEventListener('click', function () {
      var show = reveal.getAttribute('aria-pressed') !== 'true';
      reveal.setAttribute('aria-pressed', show);
      reveal.textContent = show ? 'Hide original values' : 'Show original values';
      $$('.v-orig').forEach(function (el) { el.hidden = !show; });
      $$('.v-masked').forEach(function (el) { el.hidden = show; });
    });
  }
})();
