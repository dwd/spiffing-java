# Repository working instructions

- Always commit completed work. Multiple commits for a single user instruction
  are fine; use coherent commits and include all changes made for that work.
  Leave unrelated user changes untouched.
- Give every commit a short, descriptive headline followed by a detailed body.
  The body must explain the code changes and their purpose, and describe testing:
  tests added or changed, commands run, results, and any verification limitations.
  Do not claim checks that were not performed.
- Always add useful tests for behavior changes. Cover expected behavior, failure
  cases, and relevant security or policy boundaries. Refactor existing code when
  needed to make behavior testable rather than leaving it untested. For changes
  limited to documentation or build configuration, use the relevant existing
  checks; add regression coverage when it would detect a meaningful failure.
- Run the relevant tests and build checks before committing. For library changes,
  use `mvn verify`, including the upstream policy vectors and JAR packaging.
  When changing the Java baseline or dependencies, build and run tests on Java 17
  and check relevant dependency compatibility. Use `mvn clean verify` when stale
  compiled classes could conceal compatibility problems. Offline mode (`-o`) is
  appropriate when dependencies are already cached.
- Maintain the overall design in `doc/design.md`, including decisions,
  assumptions, scope, test coverage, and known limitations. Keep `README.md`
  focused on usage, building, and externally relevant compatibility behavior.
- Stop and ask questions when requirements or consequential design choices need
  clarification. Record the resulting decisions in the design document. Proceed
  with routine implementation choices and work already authorized by the user.

## Project context

This project is the policy-driven Spiffing Java library, ported from the C++
implementation in `../spiffing`. It provides Open XML SPIF policies, labels,
clearances, markings, validation, access decisions, equivalence translation, and
XML/NATO/ASN.1 codecs. The Maven coordinates are `io.cridland:spiffing` and the
Java package is `io.cridland.spiffing`.

The minimum runtime is Java 17, matching the user's Openfire minimum. The
consumer plugin is in `../openfire-spiffing-plugin` and Openfire source is in
`../openfire`. Follow `README.md` for building and local Maven installation.
This repository builds a library JAR, not an Openfire plugin; JSP compilation,
server deployment, and plugin lifecycle behavior belong to the consumer.

The test suite uses copied upstream policy fixtures, expected markings and
access decisions, XML/NATO/DER round trips, fixed ASN.1 byte vectors, and focused
failure and policy-boundary tests. Tests must remain self-contained and must not
require a sibling checkout or a running Openfire server. Preserve the upstream
MIT attribution and document intentional differences from the C++ behavior.
