# Report UI (Cloudscape)

The React app that draws every HTML report with the
[Cloudscape Design System](https://cloudscape.design/): the single-account and
multi-account assessment reports and the "Changes since last assessment" page.

Python builds each report's data model (`report_template.build_report_data()`
and `assessment_history.render_changes.changes_page_data()`); this app only lays
it out. The model's shape is [`src/types.ts`](src/types.ts).

## Build

The build is committed, so the Lambda and CodeBuild never run Node. After any
change here:

```bash
cd report-ui
npm ci
npm run build
```

`npm run build` type-checks, writes `report-ui.js`, `report-ui.css`, and
`manifest.json` to
`aiml-security-assessment/functions/security/generate_consolidated_report/report_ui/`,
and records a hash of the sources. `tests/test_report_ui_bundle.py` fails if the
sources change without a rebuild.

## Rules

- Use Cloudscape components and design tokens; `src/report.css` holds layout
  helpers only and sets no colors.
- Render finding text as text. Rich text (`RichText`) carries only the bold
  runs and HTTPS links that Python's `rich()` produced from its own constants.
- Keep the light/dark choice in `localStorage` under `theme`, shared by every
  report file.
