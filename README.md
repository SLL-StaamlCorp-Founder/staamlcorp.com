# StaamlCorp.com

Corporate website for **StaamlCorp** — cybersecurity intellectual property licensing.

## About

StaamlCorp licenses patented cybersecurity technology covering **Temporal Security Discontinuity** — cached executable content persisting across security policy transitions.

- **Patent:** U.S. Application No. 19/640,793 (Track One Prioritized Examination, 30 Claims)
- **Discovery:** LDB-01 / Apple webkit-294380 — 3-year undetected bypass of iOS Lockdown Mode
- **Domain:** [staamlcorp.com](https://staamlcorp.com)

## Technology Stack

Static HTML/CSS/JS site hosted on GitHub Pages.

- **Pages:** 14 HTML pages (home, about, licensing, assessment, team, blog articles, contact, compliance, privacy, terms, accessibility)
- **Styles:** Single `styles.css` with CSS custom properties
- **Security Framework:** Client-side demonstration of the patented TSB architecture (Qeratheon-1, Layer 2–4 derivatives, orchestrator, service worker)
- **Hosting:** GitHub Pages with custom domain via `CNAME`

## Structure

```
├── index.html                  Home page
├── about.html                  Origin story and timeline
├── services.html               Licensing tiers and patent claims
├── assessment.html             Interactive risk questionnaire
├── team.html                   Founder profile
├── blog.html                   Insights index
├── blog-*.html                 Individual articles (3)
├── contact.html                Contact form and details
├── compliance.html             Certification standards
├── privacy.html                Privacy policy
├── terms.html                  Terms of service
├── accessibility.html          Accessibility statement
├── styles.css                  Global stylesheet
├── qeratheon-core.js           Qeratheon-1 encryption primitive
├── staaml-tsb.js               Temporal Security Binding engine
├── staaml-layer2-governance.js Layer 2 derivatives
├── staaml-layer3-infrastructure.js Layer 3 derivatives
├── staaml-layer4-verification.js   Layer 4 derivatives
├── staaml-orchestrator.js      TSB orchestrator
├── staaml-sw.js                Service worker
├── staaml-agents.js            Agent integration layer
├── staaml-debug-gate.js        Production console gating
├── cookie-consent.js           Cookie consent banner
├── logo.svg / logo-light.svg   Brand logos
├── favicon.svg / favicon-*.png Favicon assets
├── site.webmanifest            PWA manifest
└── CNAME                       GitHub Pages custom domain
```

## License

All rights reserved. See [LICENSE](LICENSE).
