# vulnsig.io — Site Specification

## Overview

vulnsig.io is a standalone Next.js application that promotes, explains, and provides interactive exploration of the VulnSig visual encoding system for CVSS vulnerability vectors. The site serves as both a marketing page and a functional tool.

**Headline:** "CVSS is more than a number"

**Core message:** CVSS scores compress rich vulnerability data into a single number. vulnsig exposes that information as a compact, readable visual glyph — every metric encoded, nothing lost.

## Tech Stack

- **Framework:** Next.js (App Router)
- **Styling:** Tailwind CSS
- **Glyph rendering:** `vulnsig-react` (React component library, imported from npm)
- **API route SVG generation:** `vulnsig` (core TS library, imported from npm)
- **Theme:** Dark by default (the glyphs are designed for dark backgrounds)
- **Fonts:** Monospace for technical elements (vector strings, metric values), clean sans-serif for body text. Choose something with character — avoid Inter/Roboto.

## npm Dependencies

```
vulnsig          # Core TS library: vector → SVG string
vulnsig-react    # React component: <VulnSig vector="..." />
```

The `vulnsig-react` component accepts at minimum:

```tsx
<VulnSig
  vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
  size={120} // pixel size
  score={10.0} // optional override, auto-calculated if omitted
/>
```

The core `vulnsig` library exports at minimum:

```ts
import { renderGlyph, scoreToHue } from "vulnsig";
const svgString = renderGlyph({ vector: "...", size: 120 });
const { hue, sat } = scoreToHue(9.3);
```

**Important:** The site should treat the vulnsig libraries as black boxes. Do not reimplement glyph rendering, color mapping, or metric parsing. Import and use the libraries. If something is needed that isn't exported, note it as a required API addition rather than reimplementing.

---

## Page Structure

The site is a single page with a tabbed lower section:

```
vulnsig.io
├── Hero Section          — Headline + annotated hero glyphs
├── Builder Bar           — Sticky compact bar, always visible after hero
├── Tabbed Section
│   ├── Gallery           — Famous vulnerabilities showcase
│   ├── Legend            — Visual encoding reference
│   └── Packages & API   — Install snippets, REST API docs
```

---

## 1. Hero Section

### Purpose

First impression. The visitor sees famous vulnerability glyphs at large size with animated callout annotations that teach the visual language inline. No "what is this?" paragraph needed — the callouts _are_ the explanation.

### Layout

Full-width dark section. The headline "CVSS is more than a number" is prominent but not overwhelming. Below it, a brief subhead: something like "vulnsig encodes every CVSS 4.0 metric into a compact visual glyph. Each shape, pattern, and color tells you something specific about the vulnerability."

Below the text, 3–4 hero glyphs rendered large (200–240px) in a horizontal row. Each glyph has animated callout annotations.

### Annotated Hero Glyphs

Each hero glyph is a famous vulnerability chosen to showcase different visual features. The callouts are thin leader lines from a specific visual feature to a small text label.

**Suggested hero set (choose 3–4):**

| Vulnerability              | Score | Why it's a good hero                                                                     |
| -------------------------- | ----- | ---------------------------------------------------------------------------------------- |
| Log4Shell (CVE-2021-44228) | 10.0  | Everything maxed — split ring, spikes, all sectors bright. Shows the "worst case" glyph. |
| Heartbleed (CVE-2014-0160) | 8.7   | Only one sector lit — visually distinctive, great for showing CIA independence.          |
| Spectre (CVE-2017-5715)    | 5.6   | Segmented ring, blunt star, split band — shows the most visual features in one glyph.    |
| Phishing Link (example)    | 5.1   | Clean perimeter (UI:A) — shows the calm, no-spikes state. Contrast with Log4Shell.       |

**Callout content per glyph (4–5 callouts each):**

Callouts should point to specific visual features and explain what metric they encode. Examples:

- "8 points → Network attack vector" (pointing at star tips)
- "Sharp star → Low complexity" (pointing at star valleys)
- "Bright sectors → High impact on C, I, A" (pointing at ring)
- "Spikes → No user interaction needed" (pointing at spikes)
- "Split ring → Downstream systems affected" (pointing at ring gap)
- "Segmented → Attack requires preconditions" (pointing at cuts)
- "Color → Overall severity score" (pointing at hue ring)
- "Smooth edge → User action required" (pointing at clean perimeter)
- "Thin outline → No privileges needed" (pointing at star stroke)

Each hero glyph should emphasize _different_ features in its callouts. Don't repeat the same callout across all glyphs.

### Callout Animation

Callouts fade/slide in sequentially with a staggered delay (200–300ms between each). This builds understanding progressively — the viewer processes one encoding at a time. The leader lines can draw in (stroke-dashoffset animation) before the text label appears.

### Callout Visual Style

- Thin leader lines (1px, muted color like `rgba(255,255,255,0.3)`)
- Small dot at the anchor point on the glyph
- Text label in monospace, small size (11–13px)
- Labels positioned to avoid overlapping the glyph or each other
- The metric value (e.g., `AV:N`) can be highlighted in the label in a brighter or accent color

### Vectors for Hero Glyphs

```
Log4Shell:   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
Heartbleed:  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N
Spectre:     CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N
Phishing:    CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
```

---

## 2. Builder Bar

### Purpose

An always-available interactive tool for exploring how metrics map to visual features. Sits between the hero section and the tabbed section, becomes sticky on scroll.

### Collapsed State (Sticky)

A horizontal bar approximately 70–80px tall containing:

- The current glyph (rendered at 56–64px)
- The vector string (editable text input, monospace)
- The auto-calculated score (displayed as a colored badge using `scoreToHue`)
- An expand/collapse toggle

This bar becomes `position: sticky` at the top of the viewport once the user scrolls past it. It stays visible while the user browses the gallery, legend, or API tabs below.

### Expanded State

When expanded, the builder reveals a metric picker panel below the compact bar. This panel contains controls for all 11 CVSS 4.0 base metrics:

**Exploitability metrics:**

- AV: Attack Vector — segmented button: N / A / L / P
- AC: Attack Complexity — toggle: L / H
- AT: Attack Requirements — toggle: N / P
- PR: Privileges Required — segmented button: N / L / H
- UI: User Interaction — segmented button: N / P / A

**Vulnerable system impact:**

- VC: Confidentiality — segmented button: H / L / N
- VI: Integrity — segmented button: H / L / N
- VA: Availability — segmented button: H / L / N

**Subsequent system impact:**

- SC: Confidentiality — segmented button: H / L / N
- SI: Integrity — segmented button: H / L / N
- SA: Availability — segmented button: H / L / N

Layout: metrics arranged in a compact grid, grouped by category. Each control is labeled with the metric abbreviation and full name. The selected value for each metric is highlighted.

### Bidirectional Sync

- Changing any metric toggle updates the vector string and re-renders the glyph
- Editing the vector string directly updates all metric toggles
- The score recalculates on every change

### Visual Feedback

When a metric value changes, the corresponding visual feature on the glyph should briefly highlight or pulse to draw attention to the connection between the control and the visual output.

### Gallery Integration

Clicking "Try this vector" on any gallery card loads that vector into the builder — the metric toggles update, the glyph re-renders, and if the builder is collapsed, it briefly expands to show the change before re-collapsing.

---

## 3. Tabbed Section

Three tabs below the builder bar. The tabs should feel like part of the same page, not separate views. Tab content loads instantly (no route change).

### Tab: Gallery

A showcase of famous vulnerabilities rendered as glyphs with explanatory context.

**Card layout:** Grid of cards, each containing:

- Glyph (rendered at 96–120px)
- Vulnerability name and CVE ID
- CVSS 4.0 Base Score (colored badge)
- The vector string (monospace, compact)
- 1–2 sentence description of what the glyph's visual features tell you about this vulnerability
- "Try in builder" button (loads vector into builder bar)

**Vulnerability set (16 vectors):**

| Name               | CVE            | Score | Vector                                                 |
| ------------------ | -------------- | ----- | ------------------------------------------------------ |
| Log4Shell          | CVE-2021-44228 | 10.0  | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H |
| Heartbleed         | CVE-2014-0160  | 8.7   | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N |
| Spectre            | CVE-2017-5715  | 5.6   | AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N |
| EternalBlue        | CVE-2017-0144  | 9.3   | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N |
| Dirty COW          | CVE-2016-5195  | 7.3   | AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N |
| BlueKeep           | CVE-2019-0708  | 9.3   | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L |
| Phishing Link      | —              | 5.1   | AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N |
| USB Physical       | —              | 7.3   | AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N |
| Rowhammer          | CVE-2015-0565  | 5.9   | AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N |
| KRACK              | CVE-2017-13077 | 5.6   | AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N |
| Shellshock         | CVE-2014-6271  | 9.2   | AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H |
| POODLE             | CVE-2014-3566  | 2.3   | AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N |
| Meltdown           | CVE-2017-5754  | 5.6   | AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N |
| Sudo Baron Samedit | CVE-2021-3156  | 8.4   | AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N |
| DDoS Amplification | —              | 8.7   | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H |
| XSS Stored         | —              | 5.1   | AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N |

**Sorting/filtering:** Allow sorting by score (ascending/descending) and optionally filtering by visual feature (has spikes, has split band, is segmented, etc.).

### Tab: Legend

A comprehensive visual encoding reference — the human-readable version of the spec. This should be richly illustrated with example glyphs rendered via `vulnsig-react`.

**Sections:**

1. **Color Hue** — Score-to-color spectrum bar with labeled score ticks. Show 4–5 example glyphs at different scores side by side to demonstrate the progression.

2. **Star Points** — AV encoding. Show the four star shapes (8/6/4/3 points) side by side with labels: Network, Adjacent, Local, Physical.

3. **Star Pointiness** — AC encoding. Show sharp (AC:L) vs blunt (AC:H) side by side.

4. **Star Outline** — PR encoding. Show thin/medium/thick stroke examples.

5. **Ring Brightness** — CIA impact encoding. Show a ring with one sector bright, one mid, one dark. Label the three sectors.

6. **Split Band** — SC/SI/SA encoding. Show split vs unsplit side by side.

7. **Ring Segmentation** — AT encoding. Show segmented vs solid side by side.

8. **Spikes and Bumps** — UI encoding. Show all three states: spikes (UI:N), bumps (UI:P), clean (UI:A).

9. **Star Fill** — Score color at full intensity in the star center.

10. **Summary Table** — Quick reference mapping each visual property to its metric and encoding.

Each section should include a brief description of what the metric means in security terms, not just what the visual looks like. For example, for AV: "Attack Vector describes how the vulnerability is exploited. Network (AV:N) means the attacker can exploit it remotely over the internet. Physical (AV:P) means they need to physically touch the device."

**Legend glyphs** should be rendered using `vulnsig-react` with carefully chosen vectors that isolate the feature being explained. For instance, when showing star pointiness, use two vectors that differ only in AC.

### Tab: Packages & API

**Package install snippets:**

```
npm install vulnsig           # Core TS — SVG string output
npm install vulnsig-react     # React component
pip install vulnsig            # Python — SVG string output
```

Each with a minimal usage example (3–5 lines).

**Links:**

- GitHub: github.com/vulnsig/vulnsig-ts
- GitHub: github.com/vulnsig/vulnsig-py
- GitHub: github.com/vulnsig/vulnsig-react
- npm: npmjs.com/package/vulnsig
- npm: npmjs.com/package/vulnsig-react
- PyPI: pypi.org/project/vulnsig

**REST API documentation:**

Endpoint: `GET https://vulnsig.io/api/v1/svg`

| Parameter | Type   | Required | Default | Description                        |
| --------- | ------ | -------- | ------- | ---------------------------------- |
| `vector`  | string | yes      | —       | CVSS 4.0 vector string             |
| `size`    | number | no       | 120     | Rendered width/height in pixels    |
| `score`   | number | no       | auto    | Override the auto-calculated score |

Response: `Content-Type: image/svg+xml`

**Usage examples:**

```html
<!-- Embed as image -->
<img
  src="https://vulnsig.io/api/v1/svg?vector=CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
/>

<!-- In markdown -->
![Log4Shell](https://vulnsig.io/api/v1/svg?vector=CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H&size=64)
```

```bash
# curl
curl "https://vulnsig.io/api/v1/svg?vector=CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" -o glyph.svg
```

---

## 4. API Route

### Implementation

A Next.js API route at `/api/v1/svg` that uses the core `vulnsig` library (not React) to generate SVG strings server-side.

```
app/api/v1/svg/route.ts
```

- Parse query parameters: `vector`, `size`, `score`
- Validate vector string format
- Call `renderGlyph({ vector, size, score })`
- Return with `Content-Type: image/svg+xml` and appropriate cache headers
- On invalid input, return 400 with a JSON error body

**Cache headers:** `Cache-Control: public, max-age=31536000, immutable` — the same vector always produces the same SVG, so cache aggressively.

**Error responses:**

```json
{ "error": "Invalid CVSS vector", "detail": "Missing required metric: AV" }
```

---

## Design Notes

### Overall Aesthetic

The site should feel technical and precise but not sterile. Think security tooling with good taste — dark backgrounds, monospace accents, restrained color use. The glyphs themselves provide all the color the page needs. Surrounding UI should be muted so the glyphs pop.

Avoid: gradients on buttons, rounded-everything, pastel accents, or anything that undercuts the security/technical credibility.

### Responsive Behavior

- **Desktop (>1024px):** Hero glyphs in a row, builder bar full-width, gallery in a 3–4 column grid
- **Tablet (768–1024px):** Hero glyphs 2×2, gallery 2 columns
- **Mobile (<768px):** Hero glyphs stacked vertically (show 2, swipeable), builder bar collapses to glyph + score only (tap to expand), gallery single column, tabs become a dropdown or accordion

### Accessibility

- All glyphs should have `aria-label` attributes describing the vulnerability and its key metrics in plain text
- Callout animations should respect `prefers-reduced-motion`
- Tab navigation should be keyboard-accessible
- Color is never the sole differentiator — the legend explains shape, pattern, and position encodings too

### Performance

- Glyph rendering happens client-side via `vulnsig-react` (SVG, no canvas)
- No images to load — everything is vector
- The gallery can lazy-render glyphs as they scroll into view
- The API route is stateless and cacheable

---

## Data Model

No database. All vulnerability data is static and lives in a JSON file within the repo:

```ts
// data/vulnerabilities.ts
export const VULNERABILITIES = [
  {
    name: "Log4Shell",
    cve: "CVE-2021-44228",
    score: 10.0,
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    description:
      "Remote code execution in Apache Log4j. A network attacker with no privileges and no user interaction can fully compromise confidentiality, integrity, and availability — and the damage spreads to downstream systems.",
    // Hero callouts (only for hero glyphs, null for others)
    callouts: [
      {
        feature: "star-points",
        label: "8 points → Network attack",
        anchor: "top",
      },
      {
        feature: "star-shape",
        label: "Sharp → Low complexity",
        anchor: "inner-left",
      },
      {
        feature: "ring-brightness",
        label: "All bright → Full CIA impact",
        anchor: "right",
      },
      {
        feature: "spikes",
        label: "Spikes → No user interaction",
        anchor: "top-right",
      },
      {
        feature: "split-band",
        label: "Split → Downstream impact",
        anchor: "bottom-left",
      },
    ],
  },
  // ... remaining 15 vulnerabilities
];
```

Hero glyphs are a subset of the full vulnerability list, identified by having non-null `callouts`.

---

## Deployment

Standard Next.js deployment. This will be deployed via AWS Amplify. The only external dependencies are the npm packages (`vulnsig`, `vulnsig-react`).

Environment variables: none required for the base site. If analytics are added later, those would be the first env vars.

---

## Future Considerations

- **CVSS 3.x support in the builder:** Add a version toggle (4.0 / 3.1 / 3.0) that adjusts available metrics and uses the library's 3.x compatibility layer when available.
- **Share URLs:** Encode the current builder vector into the URL hash so people can share links to specific glyphs.
- **Embed widget:** A "copy embed code" button that generates an `<img>` tag pointing at the API endpoint.
- **Light theme toggle:** For users who prefer light backgrounds (requires library support).
