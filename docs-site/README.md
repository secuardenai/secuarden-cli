# Secuarden CLI documentation site

An Astro Starlight documentation site published from `main` to
**https://secuardenai.github.io/secuarden-cli/** using GitHub Pages.

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
`sidebar` in `astro.config.mjs`. Use project-root-relative internal links beginning with `/secuarden-cli/` and trailing
slashes. Keep commands grounded in the intended CLI release.

Existing repository `docs/` files remain engineering references during migration.
Do not blindly copy them: audit stale product claims and move user-facing content
into the website deliberately. CLI-reference generation and release versioning
are follow-up work, not implemented by this scaffold.

## GitHub Pages deployment

In repository Settings → Pages, select **GitHub Actions** as the build source.
The Documentation workflow checks and builds pull requests without deploying them.
Pushes to `main` that change the site or workflow publish after the build and
internal link checks succeed. To redeploy manually, run the Documentation workflow
on `main` from the Actions tab.

The deploy job uses the `github-pages` environment with `pages: write` and
`id-token: write`; no personal access token or custom DNS is required.
The organization root URL is a separate site; these docs use `/secuarden-cli/`.
Astro's `site` and `base`, content links, and the link checker must agree on this
project path. Search assets and navigation are generated under that base.

GitHub Pages does not process `public/_headers` (retained for other static hosts).
The HTML noindex metadata and robots.txt remain in place while scaffold content
is reviewed; publication does not remove those indexing safeguards.

## Before production publication

- Validate all commands against the selected released CLI version.
- Audit policy/enforcement claims against actual recorder behavior.
- Complete the reference pages and release/upgrade guidance.
- Confirm the sidebar, mobile layout, search and accessibility.
- Remove the development banners after review.
- Remove `noindex` from `astro.config.mjs` and `public/_headers`, and update
  `public/robots.txt` to permit indexing. Keep previews excluded separately.
- Verify the GitHub Pages deployment, navigation, assets, and search.
