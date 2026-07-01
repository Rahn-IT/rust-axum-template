# Agent Working Rules

## SQL Queries

- Use compile-time verified SQL queries.
- If a query cannot be compile-time verified, ask for explicit confirmation before using it.
- Do not silently replace compile-time checked queries with unchecked runtime queries.
- Keep SQLx query metadata in sync with compile-time checked SQL.
- Use `just sqlx` for SQLx metadata updates.
- If the database is not online or SQLx preparation needs database access, ask the user before running it so they can start the database first.
- Do not delete SQLx cache files as a workaround for compile errors.

## Scope Control

- Keep changes scoped to the user request.
- Do not make larger or adjacent changes just because they seem useful.
- If a broader change appears to be the smartest technical move, explain why and ask for confirmation before doing it.
- When a requested change is ambiguous, ask before implementing UI or workflow changes.
- Prefer the smallest viable fix first, especially for UI issues.

## Change Style

- Prefer minimal, direct changes.
- Maintainable code is more important than cleverness or fancy UI.
- Avoid unnecessary abstractions, redesigns, and refactors.
- Preserve existing project patterns unless the requested change requires otherwise.
- Preserve existing layout style unless the user asks for a redesign.
- Avoid adding extra sections, wrappers, visual structure, or workflow steps unless they are needed for the requested change.

## Verification

- Run `cargo fmt --check` and `cargo check` after code changes.
- If a check cannot be run, report why.

## Maintaining These Rules

- Occasionally consider whether lessons from the current work should be added to this file.
- Ask the user before adding or changing rules in `AGENTS.md`.
