---
description: For every software testing and qa automation related task.
alwaysApply: false
---
Project Development Guidelines

The following guidelines instruct the agent on best practices for project development, testing, code reviews, and implementation. It also specifies the tools available to the agent.

🤖 Agent & Tooling Guidelines
Task Management
● Use the `sequentially mcp` to break down complex tasks into smaller, manageable, and actionable steps. This ensures a structured and methodical approach to development and testing.
Manual Testing & Exploration
● When manual inspection or debugging in a browser is required, use the `playwright mcp`. This is useful for understanding application behavior before writing automated tests or for verifying changes that are difficult to automate.
Technical Documentation & Research
● For accessing technical documentation, such as the OWASP Application Security Verification Standard (ASVS), OWASP Cheat Sheet Series, or the official Playwright documentation, use the `context7 mcp`. This ensures you are referencing up-to-date and authoritative sources for security and testing best practices.
Workspace Documentation
● All project documentation should be maintained in the graph knowledge memory. Use the `graph knowledge memory mcp` to write, update, or delete documentation. This keeps documentation in sync with the codebase.

✅ Automated Testing Guidelines
Test Scope
● Create positive and negative tests to ensure comprehensive coverage. Focus on critical user paths and common error states.
● One positive test per feature is sufficient unless more comprehensive testing is specifically requested.
Test Execution
● Do not display Playwright reports in the UI.
● Run tests in the background using terminal commands.
● Analyze test results programmatically and provide a summary of outcomes.
● Only show test failures or issues that need attention.
Test Structure
● Use clear, descriptive test names that indicate the feature being tested.
● Include proper test setup (`beforeEach`) and cleanup (`afterEach`) to ensure test isolation.
● Use reliable selectors, prioritizing `data-testid` attributes to decouple tests from DOM structure changes.
● Keep tests focused and atomic – one test per specific functionality.
● Extract shared test logic (e.g., login flows, form filling) into reusable helpers.
● Use Page Object Models (POM) or test abstraction layers for interacting with the UI.
● Maintain a consistent naming convention for `data-testid` attributes to simplify selection.
Test Names & Organization
● Name test files after the feature they are testing (e.g., `user-login.spec.ts`) and not generic names like “bug-fix” or “new-feature”.
● Group tests by feature or domain in clearly named folders.
● Avoid duplicating similar test steps across different files.
● Ensure shared flows are placed in a common location (e.g., `utils/testHelpers.ts`).

waiting Strategy
● Avoid fixed waits (`page.waitForTimeout()`) as they lead to flaky and slow tests.
● Use Playwright's auto-waiting mechanisms and web-first assertions (`expect(locator).toBeVisible()`) which are reliable and efficient.
● For complex scenarios, wait for specific network responses (`page.waitForResponse()`) or load states (`page.waitForLoadState('networkidle')`) instead of arbitrary delays.

Test Data Management
● Avoid hardcoding test data directly in test files.
● Use test data factories to generate dynamic and unique data for each test run, ensuring test independence.
● Implement cleanup strategies using `afterEach` or `afterAll` hooks to remove test data after execution, preventing state leakage.

🔍 Code Review Guidelines
Change Validation
● Always review all changes holistically across the entire codebase.
● Ensure changes are consistent across all related files.
● Verify that modifications don’t break existing functionality.
● Check for orphaned references when files are deleted or renamed.
● Identify and eliminate duplicated logic across test and utility files.
● Review for repeated selectors or assertions that can be abstracted.
● Ensure that no hardcoded URLs, credentials, or other sensitive data are present in the code.
● Verify that robust waiting strategies are used in place of fixed timeouts.
Documentation Consistency
● If files are deleted, edit the `README.md` or relevant files in the `/docs` directory to remove any references to them.
● If new files are created, update the `README.md` or other relevant documentation to include information about the new files and their purpose.
● Update project structure diagrams if significant changes are made (e.g., in `docs/architecture.md`).
● Keep `package.json` scripts aligned with actual test files.
Integration Checks
● Verify imports/exports are updated when files are moved or renamed.
● Check that routing still works after page component changes.
● Ensure CSS classes and styling remain consistent.
● Validate that `data-testid` attributes are properly added for new interactive elements.

🧱 Implementation Standards
Component Development
● Add appropriate `data-testid` attributes for all testable elements to ensure stable selectors.
● Maintain consistent styling and UX patterns.
● Follow existing code patterns and conventions.
● Prefer stronger TypeScript typing.
● Reuse existing UI components instead of creating new ones for the same behavior.
● Create and document shared logic in common utility files.
Feature Implementation
● Implement features incrementally and test at each stage.
● Maintain backwards compatibility unless breaking changes are intentional.
● Evaluate the performance impact of new features.
● Follow accessibility best practices. Consult relevant guidelines using the `context7 mcp` if needed.
● Ensure all implementations adhere to security best practices. Use the `context7 mcp` to consult the OWASP ASVS or relevant cheat sheets.
● All features should prioritize performance and be as fast as possible.

♻️ Code & Test Reusability
● Extract shared test flows and utilities into central helper modules.
● Use Page Object Model (POM) patterns to encapsulate UI behavior. Introduce a `BasePage` for shared logic and structure POMs in a layered architecture (e.g., Pages → Components → Utilities).
● Ensure consistent naming and structure across components and tests.
● Avoid writing the same assertions or flows in multiple places—refactor them.

🌍 Environment & Configuration
● Centralize all environment-specific configurations (e.g., base URLs, API endpoints) in a dedicated configuration file that reads from environment variables.
● Do not hardcode URLs or credentials in test files.
● Use `.env` files to manage environment variables for local development.

🚀 Performance & CI/CD
● Configure Playwright to run tests in parallel to reduce execution time in CI/CD pipelines.
● Use test sharding to distribute large test suites across multiple machines for faster feedback.
● Optimize CI configurations to only run necessary steps. For example, install only the required browsers.
● Configure test retries in the `playwright.config.ts` to handle flaky tests in CI.
● Generate and store test artifacts like traces, videos, and screenshots only on failure to save resources.

Tools allowed to use
● Use Playwright’s built-in utilities and methods.
● Use the provided MCP playwright server to access the application.
● Use the `playwright mcp` for manual browser interaction and inspection.
● Use the `sequentially mcp` to structure and plan task execution.
● Use the `context7 mcp` to retrieve technical documentation (e.g., OWASP, Playwright docs).
● Use the `graph knowledge memory mcp` to manage documentation.