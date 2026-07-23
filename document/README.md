# SkillHub Docs Site

`document/` contains the Docusaurus source for the public documentation site served at `https://www.astron-skillhub.org/`.

## Local Development

Install dependencies:

```bash
cd document
npm install
```

Start the docs dev server:

```bash
npm run start
```

Build the production site:

```bash
npm run build
```

## Publishing

The repository includes a GitHub Actions workflow at `.github/workflows/publish-docs-site.yml`.

- Pushes to `main` that modify `document/**` or the workflow file trigger an automatic docs build and GitHub Pages deployment
- The custom domain is configured through `document/static/CNAME`
- Legacy website URLs such as `quickstart.html` and `guide/skill-publish.html` are redirected to the current Docusaurus routes via `plugin-client-redirects`

## Sync Rule

To keep `https://www.astron-skillhub.org/` aligned with the latest repository content:

- Treat `document/` as the source of truth for the public docs site
- Update `document/docs/**` whenever product messaging or public-facing workflow documentation changes materially
- Keep redirects updated when replacing or renaming public routes
