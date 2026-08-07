<p align="center">
  <img src="./contributing-styles.svg" alt="Contributing to Wippa" width="100%">
</p>

Thanks for your interest in Wippa. We're in early OSS and want to keep the feedback loop tight.

## Reporting Issues

Open a GitHub issue for:

- **Bugs** — include the full command you ran, the output, and your OS/Docker version.
- **Framework requests** — we support 18 frameworks today. If yours is missing, open an issue with the framework name and links to its package on PyPI/npm.
- **Security concerns** — if you find a bypass in the scanner or sandbox, open an issue with `[SECURITY]` in the title.

## Pull Requests

We're not actively merging PRs yet — we're in "listen and support" mode. That said:

1. Fork the repo.
2. Create a feature branch (`git checkout -b feature/your-idea`).
3. Make your changes.
4. Run `npm test` — all tests must pass.
5. Open a PR with a clear description of what and why.

We'll review and merge once the project stabilizes.

## Development Setup

```bash
git clone https://github.com/wippa-studios/wippa
cd wippa
npm install
npm run build
npm test
```

You'll need:

- **Node.js 20+**
- **Docker** (for `wippa run`)
- **git** (for cloning repos)

gVisor is optional. Install `runsc` separately if you want `--gvisor` support.

## Code Style

- TypeScript, strict mode.
- No external dependencies beyond what's in `package.json`.
- Tests go in `tests/` mirroring `src/` structure.
- Inline styles, no comments.
