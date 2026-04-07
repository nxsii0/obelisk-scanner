# CONTRIBUTING

Contributions to OBELISK SCANNER are welcome. Please follow these guidelines:

## ADDING MODULES

If you'd like to add new scanners or data providers:
1.  Fork the repository.
2.  Create a feature branch.
3.  Implement your provider in `obeliskscan/providers/`.
4.  Ensure it adheres to the `HttpPolicy` and uses the shared `get_session` for efficiency.

## REPORTING BUGS

Please use the GitHub Issue tracker to report any bugs or vulnerabilities in the tool itself.

## STYLE

Keep code clean, modular, and use `rich` for any CLI additions. No absolute paths.

---

MIT License (c) 2026 Admin
