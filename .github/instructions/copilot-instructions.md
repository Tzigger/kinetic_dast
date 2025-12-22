# Copilot instructions (Kinetic DAST)

## Big picture
- This repo is a TypeScript DAST engine built on Playwright.
- Flow: CLI/config → `ConfigurationManager` validates config → `ScanEngine` orchestrates scanners → scanners run detectors → reporters emit Console/JSON/HTML/SARIF.
- Safety: `ScanEngine` enforces production guardrails; for non-local targets it auto-enables `safeMode` unless explicitly set.

## Key entrypoints to read first
- CLI: [src/cli/index.ts](../src/cli/index.ts)
- Orchestrator: [src/core/engine/ScanEngine.ts](../src/core/engine/ScanEngine.ts)
- Config loading/validation: [src/core/config/ConfigurationManager.ts](../src/core/config/ConfigurationManager.ts)
- Detector selection: [src/utils/DetectorRegistry.ts](../src/utils/DetectorRegistry.ts) + `registerBuiltInDetectors()` (see `src/utils/builtInDetectors.ts`)
- Public API surface: [src/index.ts](../src/index.ts)
- Config types (keep in sync with CLI + engine): [src/types/config.ts](../src/types/config.ts)

## Project conventions that matter
- Strict TS is enforced, including `noPropertyAccessFromIndexSignature`.
  - Example: access detector tuning as `config.detectors.tuning?.['sqli']` (not `.sqli`).
- Prefer config-driven behavior over new classes.
  - Example: “single-page scan” is `maxDepth: 0` + `maxPages: 1` (don’t duplicate scanning logic in a new “PageScanner”).
- Use the `DetectorRegistry` everywhere for detector selection (CLI/tests do this already). Call `registerBuiltInDetectors()` before using the registry.
- Avoid parallel implementations/duplicate helpers; extend existing modules instead (DRY/SOLID).
- When deleting/moving files, update exports in `src/index.ts` and chase orphaned imports.

## Build, test, lint workflows
- Build: `npm run build` (tsc → `dist/`)
- Unit tests (Jest): `npm run test:unit` (tests live under `tests/**/*.test.ts`)
- Full tests: `npm test` (Jest) and Playwright integration tests as needed
- Lint: `npm run lint`
- CLI dev run (ts-node): `npm run dev -- <url> --scan-type passive|active|both`
- Integration testing against bWAPP: see [tests/README.md](../tests/README.md) (requires local Docker bWAPP).

## Adding/extending detectors (most common extension point)
- Implement `IActiveDetector` or `IPassiveDetector` under `src/detectors/**`.
- Register in `registerBuiltInDetectors()` with stable `DetectorMetadata` (`id`, `category`, `enabledByDefault`).
- Ensure IDs/categories match `DetectorRegistry` pattern matching (`enabled`/`disabled` in config).

## Notes
- Path aliases exist in TS + Jest (see `tsconfig.json` and `jest.config.js`).
- No `src/i18n/` directory is present in this repo today; confirm i18n approach before adding user-facing strings.
