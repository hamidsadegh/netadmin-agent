# Errors

Command failures and integration errors.

---
## [ERR-20260528-002] pytest

**Logged**: 2026-05-28T19:25:00Z
**Priority**: low
**Status**: resolved
**Area**: tests

### Summary
A new service-detection formatting test failed because the expected rendered port/service string used the wrong separator.

### Error
```
AssertionError: assert '22/ssh/OpenSSH 9.6' in '... 22/ssh OpenSSH 9.6 ...'
```

### Context
- Command attempted: `python -m pytest`
- Related Files: `tests/test_ping_only_scan.py`, `agent/cli/formatting.py`
- Cause: test expectation assumed slash separators between all service fields, while formatter intentionally renders port/service then product/version as spaced text.

### Suggested Fix
Keep the formatter output and align the test expectation with the intended compact display format.

### Metadata
- Reproducible: yes
- Related Files: tests/test_ping_only_scan.py, agent/cli/formatting.py

### Resolution
- **Resolved**: 2026-05-28T19:25:00Z
- **Commit/PR**: pending
- **Notes**: Updated the test expectation to match the actual compact formatter output.

---
