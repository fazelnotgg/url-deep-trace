# Contributing to @fazelstudio/url-deep-trace

We welcome contributions to this URL security analysis engine.

## Getting Started

1. Fork & clone the repository
2. Install: `npm install`
3. Install optional deps for screenshot tests: `npm install playwright`
4. Create a branch: `git checkout -b feat/your-feature`

## Development

```bash
# Run basic tests
npm test

# Run all tests (including security & optimization)
npm run test:all

# Run test server
npm run server
```

## Adding a New Analysis Module

1. Create `src/your-module.js`
2. Export a class or function
3. Integrate in `src/index.js` and add to `src/tracer.js` if needed
4. Add tests in `test/`
5. Update README API reference

## Commit Guidelines

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add DNS-over-HTTPS resolver module
fix: handle timeout edge case in tracer
docs: update risk scoring formula
```

## Pull Request Process

1. Run all tests: `npm run test:all`
2. Update documentation if public API changed
3. Open a PR with a clear description

## Questions?

Open a [Discussion](https://github.com/fazelllyyy/url-deep-trace/discussions) or email zulfazlilsm@gmail.com.