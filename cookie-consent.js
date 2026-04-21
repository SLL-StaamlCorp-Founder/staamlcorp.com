/**
 * Staaml Cookie Consent Banner
 * Lightweight, accessible, GDPR-compliant cookie consent
 * Stores preference in localStorage — no cookies used for consent itself
 */
(function() {
  'use strict';

  // Exit if consent has already been given or declined
  if (localStorage.getItem('staaml_cookie_consent') !== null) {
    return;
  }

  // Inject styles
  var style = document.createElement('style');
  style.textContent = [
    '.cc-banner {',
    '  position: fixed;',
    '  bottom: 0;',
    '  left: 0;',
    '  right: 0;',
    '  z-index: 10000;',
    '  background: var(--bg-dark, #0f172a);',
    '  color: #e2e8f0;',
    '  padding: 1.25rem 1.5rem;',
    '  box-shadow: 0 -4px 20px rgba(0, 0, 0, 0.2);',
    '  font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;',
    '  font-size: 0.95rem;',
    '  line-height: 1.6;',
    '  transform: translateY(100%);',
    '  transition: transform 0.4s ease;',
    '}',
    '.cc-banner.cc-visible {',
    '  transform: translateY(0);',
    '}',
    '.cc-inner {',
    '  max-width: 1200px;',
    '  margin: 0 auto;',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  gap: 1.5rem;',
    '  flex-wrap: wrap;',
    '}',
    '.cc-text {',
    '  flex: 1;',
    '  min-width: 280px;',
    '}',
    '.cc-text a {',
    '  color: var(--accent-light, #60a5fa);',
    '  text-decoration: underline;',
    '}',
    '.cc-text a:hover {',
    '  color: #93bbfd;',
    '}',
    '.cc-buttons {',
    '  display: flex;',
    '  gap: 0.75rem;',
    '  flex-shrink: 0;',
    '}',
    '.cc-btn {',
    '  padding: 0.6rem 1.5rem;',
    '  border: none;',
    '  border-radius: 6px;',
    '  font-size: 0.9rem;',
    '  font-weight: 600;',
    '  cursor: pointer;',
    '  transition: background 0.2s ease, transform 0.1s ease;',
    '  white-space: nowrap;',
    '}',
    '.cc-btn:hover {',
    '  transform: translateY(-1px);',
    '}',
    '.cc-btn:focus-visible {',
    '  outline: 3px solid var(--accent-light, #60a5fa);',
    '  outline-offset: 2px;',
    '}',
    '.cc-btn-accept {',
    '  background: var(--accent, #3b82f6);',
    '  color: #fff;',
    '}',
    '.cc-btn-accept:hover {',
    '  background: var(--accent-light, #60a5fa);',
    '}',
    '.cc-btn-decline {',
    '  background: transparent;',
    '  color: #e2e8f0;',
    '  border: 1px solid #475569;',
    '}',
    '.cc-btn-decline:hover {',
    '  background: rgba(255, 255, 255, 0.08);',
    '}',
    '@media (max-width: 600px) {',
    '  .cc-inner {',
    '    flex-direction: column;',
    '    text-align: center;',
    '  }',
    '  .cc-buttons {',
    '    width: 100%;',
    '    justify-content: center;',
    '  }',
    '}'
  ].join('\n');
  document.head.appendChild(style);

  // Build banner DOM
  var banner = document.createElement('div');
  banner.className = 'cc-banner';
  banner.setAttribute('role', 'dialog');
  banner.setAttribute('aria-label', 'Cookie consent');
  banner.setAttribute('aria-describedby', 'cc-description');

  banner.innerHTML = [
    '<div class="cc-inner">',
    '  <div class="cc-text" id="cc-description">',
    '    We use minimal cookies and local storage to improve your experience on our site. ',
    '    No personal data is sold or shared for advertising. ',
    '    Read our <a href="privacy.html">Privacy Policy</a> for details.',
    '  </div>',
    '  <div class="cc-buttons">',
    '    <button class="cc-btn cc-btn-accept" aria-label="Accept cookies">Accept</button>',
    '    <button class="cc-btn cc-btn-decline" aria-label="Decline cookies">Decline</button>',
    '  </div>',
    '</div>'
  ].join('\n');

  document.body.appendChild(banner);

  // Show banner with animation after a brief delay
  setTimeout(function() {
    banner.classList.add('cc-visible');
    // Move focus to the banner for screen readers
    banner.querySelector('.cc-btn-accept').focus();
  }, 500);

  // Handle accept
  banner.querySelector('.cc-btn-accept').addEventListener('click', function() {
    localStorage.setItem('staaml_cookie_consent', 'accepted');
    closeBanner();
  });

  // Handle decline
  banner.querySelector('.cc-btn-decline').addEventListener('click', function() {
    localStorage.setItem('staaml_cookie_consent', 'declined');
    closeBanner();
  });

  // Handle Escape key to decline
  banner.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      localStorage.setItem('staaml_cookie_consent', 'declined');
      closeBanner();
    }
    // Trap focus within the banner
    if (e.key === 'Tab') {
      var focusable = banner.querySelectorAll('a, button');
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }
  });

  function closeBanner() {
    banner.classList.remove('cc-visible');
    setTimeout(function() {
      if (banner.parentNode) {
        banner.parentNode.removeChild(banner);
      }
    }, 400);
  }

})();
