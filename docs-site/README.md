# Secuarden CLI documentation site

An Astro Starlight documentation site published from `main` to
**https://cli-docs.secuarden.ai/** using GitHub Pages.

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
`sidebar` in `astro.config.mjs`. Use root-relative internal links beginning with `/` and trailing
slashes. Keep commands grounded in the intended CLI release.

Existing repository `docs/` files remain engineering references during migration.
Do not blindly copy them: audit stale product claims and move user-facing content
into the website deliberately. The version compatibility page targets the v0.8.1 candidate. Command-help checks
run in CI and before releases through `scripts/check-release-commands.py`; this
is not exhaustive flag-reference generation or live-agent acceptance.

## GitHub Pages deployment

In repository Settings → Pages, select **GitHub Actions** as the build source
and set **Custom domain** to `cli-docs.secuarden.ai`. Keep its DNS CNAME pointing
to `secuardenai.github.io` (without a repository path). Enable HTTPS once GitHub
has validated the domain and provisioned its certificate.
The Documentation workflow checks and builds pull requests without deploying them.
Pushes to `main` that change the site or workflow publish after the build and
internal link checks succeed. To redeploy manually, run the Documentation workflow
on `main` from the Actions tab.

The deploy job uses the `github-pages` environment with `pages: write` and
`id-token: write`; no personal access token is required in the workflow.
The custom domain serves the docs at `/`, not `/secuarden-cli/`. Astro's `site`,
content links, and the link checker target that root. Search assets and navigation
are generated under `/`.

The repository Pages custom-domain setting is required separately from DNS and
source changes. GitHub Actions deployments do not configure it from a CNAME file;
merging this PR alone cannot register the domain. The existing build/deploy
workflow remains unchanged.

GitHub Pages does not process `public/_headers` (retained for other static hosts).
The HTML noindex metadata and robots.txt remain in place until release validation and indexing approval
are complete; publication does not remove those indexing safeguards.

## Before production publication

- Validate all commands against the selected released CLI version.
- Audit policy/enforcement claims against actual recorder behavior.
- Complete the reference pages and release/upgrade guidance.
- Confirm the sidebar, mobile layout, search and accessibility.
- Remove the development banners after review.
- Remove `noindex` from `astro.config.mjs` and `public/_headers`, and update
  `public/robots.txt` to permit indexing. Keep previews excluded separately.
- Verify the GitHub Pages deployment, navigation, assets, and search.

## Corrective release preparation

See `../docs/releases/v0.8.1.md` for the release-tag discrepancy, validation
boundaries, and approval sequence. Do not remove candidate notices or publish
these preparation changes until the intended release and website updates are
approved. Confirm the downloadable artifact, not only a locally built binary.
