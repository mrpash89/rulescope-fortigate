# Contributing to rulescope

Thanks for helping. A few rules keep the tool safe to run next to production firewalls.

## Setup

There is nothing to install. rulescope uses the Python standard library only and supports Python 3.9
and later.

```bash
git clone https://github.com/mrpash89/rulescope-fortigate.git
cd rulescope-fortigate
python3 -m unittest discover -s tests          # all tests
python3 tests/bench.py 10000                   # performance on a synthetic 10k-rule base
python3 -m rulescope audit --config tests/sample.conf --html report.html
```

## Rules for every change

1. **Standard library only.** No new dependencies, at run time or in the tests.
2. **Read-only.** rulescope never changes a firewall. Do not add API calls that write, and do not
   make a remediation script run anything by itself.
3. **Config text is hostile.** Names, comments and values come from files other people send. Text
   from a config must pass through `safety.clean()` on the way in. On the way out use `catalog.q()`
   for FortiOS values, `_e()` for HTML, `safety.csv_cell()` for CSV and `safety.safe_url()` for links.
   Write files with `safety.write_restricted()`.
4. **Unknown is not a pass.** When a setting cannot be read or a rule cannot be modelled, report it
   as not assessed. Never guess a default and never show a clean result for something unread.
5. **A test with every fix.** Add a test that fails without your change. For anything that touches
   parsing or an output, also run `RULESCOPE_FUZZ_ROUNDS=2000 python3 -m unittest tests.test_fuzz`.
6. **No real data.** Never put a real configuration, hostname, address, serial number or token in a
   test, an issue or a pull request. Use `tests/sample.conf`, a synthetic config, or `--redact`.

## Pull requests

- One topic per pull request. Small pull requests are reviewed and merged faster, and they do not
  conflict with each other.
- Start your branch from the current `main`. If `main` moves, rebase your branch on it and run the
  tests again before asking for review.
- The `ci` check must pass.
- Describe what changes for the user. If behaviour, output or the snapshot format changes, add a
  line under "Unreleased" in [CHANGELOG.md](CHANGELOG.md) and update the README.
- Keep the style of the file you edit: type hints, short docstrings that say why, lines up to 120
  characters.

## Security problems

Do not open a public issue or pull request. Follow [SECURITY.md](SECURITY.md).

## License

rulescope is licensed under Apache-2.0. By submitting a contribution you agree that it is licensed
under the same terms (section 5 of the [LICENSE](LICENSE)).
