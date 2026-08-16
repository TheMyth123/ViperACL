# ViperACL Workspace Rules & Engineering Standards

## 1. Clean & Minimal Code
- Write concise, readable, and minimal code. Avoid unnecessary boilerplate, over-engineering, or speculative features.
- Eliminate code duplication and dead code by adhering to the DRY (Don't Repeat Yourself) principle.
- Use single sources of truth for configurations, data structures, and styling tokens.
- Keep functions, route handlers, and frontend scripts modular, focused, and minimal.

## 2. Zero-Trust Security & Input Validation
- **Never trust client input**: All inputs originating from the client (HTTP bodies, query params, path variables, form fields, headers) MUST be strictly validated and sanitized on the backend.
- **Strict Boundary & Whitelist Validation**:
  - Enforce bounds checking (min/max length).
  - Use strict regex and whitelist patterns rather than blacklists.
  - Reject dangerous characters (null bytes `\0`, path traversal `..`, `<script>` / HTML tags, quotes, control characters, Cypher/SQL injection tokens).
- **Safe Identifier & Path Handling**:
  - Never construct filesystem paths or database identifiers directly from raw user input.
  - Always sanitize into safe alphanumeric slugs combined with timestamps or UUID tokens (e.g. `proj_<slug>_<timestamp>`).
- **Concise Error Messages**: Do not leak internal system details, stack traces, or excessive implementation details in client-facing error responses.

## 3. UI Component & Styling Consistency
- **Single Source of Truth for Design Tokens**:
  - Every HTML page template MUST include `head_assets.html` (`{% include 'head_assets.html' %}`) within the `<head>` tag.
  - Never redefine Tailwind configurations, Google Font links, or typography scales in individual page templates.
- **Component Uniformity**:
  - Reusable partials (such as `sidebar.html` and global modals) rely on the tokens defined in `head_assets.html`.
  - Fonts, typography scales (`text-headline-md`, `text-label-sm`, `text-label-md`), colors, and spacings must render 100% identically across all application pages (Launchpad, Workspace, Global Logs).

## 4. Forensic Evidence & Comprehensive Audit Logging
- **Evidence is Key**: In offensive security and Active Directory remediation, every action must be verifiable, auditable, and logged.
- **Log Every Meaningful Action**:
  - All operations (project creation/selection/deletion, sharpHound ingest, graph clearing, ML scoring, pathfinding, privesc plan generation, remediation script writing, error rejections, and security validation failures) MUST produce structured log events using `core.logger.logger`.
  - Always provide category (`PROJECT`, `INGEST`, `PATHFINDER`, `PRIVESC`, `REMEDIATION`, `DATABASE`, `SYSTEM`, `AUTH`), a dot-delimited `event_type` (e.g. `project.created`, `ingest.completed`, `privesc.plan.built`), appropriate log severity (`INFO`, `WARNING`, `ERROR`, `CRITICAL`), `project_id` context, `source="web.app"`, and relevant non-sensitive payload `details`.

