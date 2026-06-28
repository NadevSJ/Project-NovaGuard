# NovaGuard Annotation Guidelines

These guidelines define how annotators assign a **risk label** and a **risk
score (0–100)** to each candidate URL in the NovaGuard evaluation dataset.
Consistency between annotators is essential for a credible ground-truth set.

## Label Definitions

Every URL receives one of four labels. The risk score must fall in the band
shown beside the label.

- **SCAM (75–100)** — The site exists to defraud the user. Clear intent to
  steal money, credentials, or personally identifiable information.
- **SUSPICIOUS (40–74)** — Strong red flags but not conclusively malicious.
  Mixed signals (e.g. impersonation cues without a working payment trap).
- **LIKELY_SAFE (15–39)** — Probably legitimate but with minor concerns
  (unfamiliar TLD, thin content, mismatched branding).
- **SAFE (0–14)** — Established, verifiable, no notable red flags.

## Sri Lankan Examples

- **SCAM**: `boc-onlinebanking-lk.ddns.net` cloning the Bank of Ceylon login
  screen; a Facebook page selling “Dialog 5G eSIM” for LKR 200 via a fake
  KOKO checkout; a site advertising **Sri Lanka government job vacancies**
  asking for a “registration fee” to a personal bank account.
- **SUSPICIOUS**: a Sampath Bank lookalike page (`sampath-secure[.]online`)
  whose login form does not submit anywhere, but whose copy and logo are
  cloned wholesale. Intent is plausibly malicious but unconfirmed.
- **LIKELY_SAFE**: a small Sri Lankan electronics reseller on a `.lk`
  subdomain with limited TLS history but real product listings and a
  reachable phone number.
- **SAFE**: `boc.lk`, `sampath.lk`, `dialog.lk`, `gov.lk` portals, and other
  long-established Sri Lankan brands with verifiable WHOIS and HTTPS.

## Edge-Case Resolution Rules

1. **Defunct phishing pages** (taken down, parked, or 404) keep their
   original SCAM label if archival evidence (URLScan, Wayback) shows
   prior phishing content.
2. **Look-alike domains without active phishing content** are SUSPICIOUS,
   not SCAM, unless the page itself attempts to harvest data.
3. **Legitimate-but-shady marketing pages** (aggressive upsell, no scam
   intent) are LIKELY_SAFE, never SCAM.
4. **Aged domain + new owner**: weight current content over WHOIS age.

## Inter-Annotator Conflict Resolution

1. Two annotators label each URL independently.
2. If labels match, accept the label and average the scores.
3. If labels differ by **one band** (e.g. SUSPICIOUS vs LIKELY_SAFE), a
   third annotator breaks the tie.
4. If labels differ by **two or more bands**, the three annotators meet,
   review evidence together, and reach consensus. Disagreements and the
   resolution rationale are logged in `evaluation/annotation/conflicts.jsonl`.

## Quality Checklist

Before submitting an annotation, confirm:

- [ ] The score sits inside the band for the chosen label.
- [ ] At least one piece of evidence (screenshot, WHOIS, archive link) is
      attached.
- [ ] Brand-impersonation claims cite the real brand’s canonical domain.
- [ ] No personal data from victims is included in evidence notes.
- [ ] The rationale is written in plain English (one to three sentences).
