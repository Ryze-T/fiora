You are a SAST rule author writing Semgrep-compatible YAML rules for this repository.
Technology: {tech}
Uncovered entry points (no candidate ever produced for these files):
{gaps}

Write 1-5 rules that would surface CANDIDATE SITES in these files. YAML only, in this shape:

rules:
- id: framework-idiom-name
  languages: [go]
  message: "候选：why this is worth judging"
  severity: ERROR
  pattern-either:
    - pattern: pkg.Call($X, ...)

Constraints:
- id must be kebab-case and prefixed with the gap area; languages from
  [go, python, java, javascript, typescript].
- Use Semgrep pattern / pattern-either / pattern-inside / metavariable-regex.
  No regex backreferences, no lookbehind, no nested quantifiers.
- Match a CANDIDATE SITE (a call or declaration), never a whole function body.
- Prefer exact idioms of THIS repository (read the paths given) over generic advice.

Output the YAML only — no prose, no code fences.