# Contributing to whisper

Thanks for considering a contribution. whisper is a small, privacy-first authentication library, and the bar for changes is that they keep it small and keep it honest about what it stores.

## Reporting bugs

- Search the existing [issues](https://github.com/yundore/whisper/issues) first.
- If nothing matches, [open a new one](https://github.com/yundore/whisper/issues/new) with steps to reproduce.

For anything security-sensitive, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Suggesting enhancements

Open an issue with a clear description, an example of how it would work, and why it helps. Changes that add personal-data fields to the core schema will be declined (see Privacy first, below).

## Pull requests

1. Fork the repo and branch from `main`.
2. Add tests that prove your change. The Node suite is `tests/whisper.test.js` (`npm test`); the Python suite is `examples/python/test_whisper.py` (`python -m unittest`).
3. Keep the Node and Python implementations in sync. They share an API and an on-disk format, so a change to one usually needs the same change to the other.
4. Make sure all tests pass and `npm audit` is clean.
5. Open the pull request.

## Adding language examples

New language ports are welcome. When adding one:

1. Create `examples/<language>/`.
2. Follow the same minimal schema: a user is a username and a password hash, nothing more by default.
3. Hash session and guest tokens at rest, enable SQLite foreign keys, and erase sessions and purchases on account deletion.
4. Include tests and a short README.

## Style

- Keep it simple and minimal.
- Comment only where the reason for the code is not obvious.
- Follow each language's standard conventions.

## Privacy first

Every contribution must hold the line on minimal data collection. PRs that add real names, emails, phone numbers, addresses, or other personal-data fields to the core authentication system will not be merged. If a feature seems to need personal data, open an issue first so we can find a way to do it without storing it.
