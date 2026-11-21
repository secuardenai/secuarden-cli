# Secuarden CLI documentation site

An Astro Starlight scaffold in the public CLI repository, prepared for
**https://cli-docs.secuarden.ai** on Cloudflare Pages. Nothing in this directory
creates a Cloudflare project, changes DNS, or publishes automatically.

## Develop

Use Node 24.18.0 (see `.node-version`) and npm:

```sh
cd docs-site
npm ci
npm run dev
```

The development server prints its local URL. Before submitting changes:

```sh
npm run check
npm run build
npm run preview
```

`build` creates `dist/`, indexes search with Starlight/Pagefind, and checks internal
page/asset links. It does not fetch external URLs or validate heading fragments.
Search is indexed during production builds; use `preview` to test it.
The Go build remains independent and requires no Node dependencies.

## Structure

```text
docs-site/
  astro.config.mjs          # Domain, navigation, Starlight configuration
  src/content.config.ts    # Validated documentation collection
  src/content/docs/        # Canonical content for website pages
    get-started/
    agents/
    guides/
    integrity/
    reference/
  src/styles/custom.css    # Small theme overrides
  public/                  # Favicon, Cloudflare headers, robots.txt
  scripts/check-links.mjs  # Generated-site internal link validation
```

Add a Markdown/MDX page with `title` and `description` frontmatter, then add it to
`sidebar` in `astro.config.mjs`. Use root-relative internal links with trailing
slashes. Keep commands grounded in the intended CLI release.

Existing repository `docs/` files remain engineering references during migration.
Do not blindly copy them: audit stale product claims and move user-facing content
into the website deliberately. CLI-reference generation and release versioning
are follow-up work, not implemented by this scaffold.

## Cloudflare Pages setup (when ready)

Connect the existing public `secuardenai/secuarden-cli` repository:

| Setting | Value |
| --- | --- |
| Project name | `secuarden-cli-docs` (suggested) |
| Root directory | `docs-site` |
| Build command | `npm run build` |
| Build output directory | `dist` |
| Node version | `24.18.0` (`NODE_VERSION` build variable) |
| Production branch | A designated release-docs branch after content review |
| Custom domain | `cli-docs.secuarden.ai` |

Cloudflare Git integration installs dependencies and can create branch previews.
For production, create/select a release-docs branch with audited, release-aligned
content rather than publishing this feature branch as stable documentation.
Add the custom domain through the Pages project and follow Cloudflare's DNS
instructions. No Worker, SSR adapter, database or runtime credentials are needed
for the static site. Never commit account tokens or deployment credentials.

The GitHub documentation workflow builds and uploads an artifact only; it does
not deploy. Cloudflare project configuration and domain setup remain manual.

## Before production publication

- Validate all commands against the selected released CLI version.
- Audit policy/enforcement claims against actual recorder behavior.
- Complete the reference pages and release/upgrade guidance.
- Confirm the sidebar, mobile layout, search and accessibility.
- Remove the development banners after review.
- Remove `noindex` from `astro.config.mjs` and `public/_headers`, and update
  `public/robots.txt` to permit indexing. Keep previews excluded separately.
- Configure Cloudflare Pages and the custom domain; verify the published result.
