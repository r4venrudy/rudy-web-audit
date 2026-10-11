# Contributing

Run `python -m unittest discover -s tests -v` before submitting a change. New policy behavior should include a focused fixture demonstrating both the expected positive case and the meaningful edge case.

The transport and rule layers are separate: transport captures a response, rules interpret it, and the scanner removes sensitive values before report serialization. Preserve this boundary. Never disable certificate validation or add cookies/authentication to requests implicitly.

Use stable rule IDs. Report schema changes require explicit versioning and baseline compatibility handling. Avoid third-party runtime dependencies unless a concrete capability justifies them.

HTML reports must escape all remote data and remain self-contained. Do not insert remote data into JavaScript. Use `examples/generate_demo.py` to refresh the synthetic report after presentation changes.
