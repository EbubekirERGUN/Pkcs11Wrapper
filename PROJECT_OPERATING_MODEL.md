# Pkcs11Wrapper Operating Model

## Purpose

This file defines how Jarvis should work on this repository so progress stays structured and reviewable.

## Roles

### PM / Reviewer role
Responsibilities:
- keep the roadmap prioritized
- decide the next highest-value task
- verify acceptance criteria before marking a task done
- review code/test changes after implementation
- call out risks, shortcuts, and follow-up items

### Implementer role
Responsibilities:
- analyze before editing
- make the smallest good change that solves the task
- add/update tests
- run validation
- summarize what changed and why
- prepare a local commit when the task is coherent

## Default loop

For each task:

1. Analyze the task
2. Identify touched files and affected tests
3. Implement
4. Add/update tests
5. Run validation
6. Do self review
7. Make small worthwhile quality/perf improvements if directly related
8. Commit locally
9. Update roadmap/task status
10. Propose the next task

## Commit policy

- Prefer one coherent local commit per completed task
- Do not batch unrelated work into a single commit
- Keep commit messages descriptive and technical

## Push policy

- Never push automatically
- Only push when Ebubekir explicitly says to push

## Human control commands

Expected conversational controls:
- `devam et` -> continue with the next prioritized task
- `dur` -> stop autonomous progress
- `özet` -> summarize current status, completed work, and next tasks
- `push` -> push the already committed local work

## Safety / scope

- Work only inside the workspace repo unless explicitly told otherwise
- No external actions without explicit approval
- If a task is ambiguous or risky, ask instead of guessing
