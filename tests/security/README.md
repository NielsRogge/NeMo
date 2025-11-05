# Security Tests

This directory contains security vulnerability tests for the NeMo framework.

## Purpose

These tests are designed to:
- **Detect** security vulnerabilities in the codebase
- **Document** the nature and impact of each vulnerability
- **Verify** that vulnerabilities exist (not to fix them)
- **Define** acceptance criteria for remediation

## Important Notes

⚠️ **These tests document vulnerabilities - they do not fix them!**

The tests in this directory are intentionally designed to:
1. Demonstrate that a vulnerability exists
2. Show attack vectors and exploitation scenarios
3. Provide clear documentation of the security concern
4. Include tests that will PASS once proper mitigations are implemented

## Test Structure

Each CVE test file follows this structure:

1. **Vulnerability Detection Tests**: Tests that verify the vulnerability exists
2. **Pattern Detection Tests**: Tests that document vulnerable code patterns
3. **Mitigation Requirement Tests**: Tests marked with `@pytest.mark.xfail` that define what proper mitigations should do (these will fail until the vulnerability is fixed)

## Running Security Tests

To run all security tests:
```bash
pytest tests/security/
```

To run tests for a specific CVE:
```bash
pytest tests/security/test_cve_008_arbitrary_file_write.py
```

To run with verbose output:
```bash
pytest tests/security/ -v
```

## Current CVEs

### CVE-008: Arbitrary File Write
- **Severity**: CRITICAL
- **File**: `test_cve_008_arbitrary_file_write.py`
- **Jira**: https://ml6team.atlassian.net/browse/DR-138
- **Description**: Potential for arbitrary file writes through path traversal and lack of path validation

## Adding New Security Tests

When adding new security tests:

1. Create a new test file named `test_cve_XXX_description.py`
2. Include comprehensive docstrings explaining the vulnerability
3. Add tests that demonstrate the vulnerability
4. Add `@pytest.mark.xfail` tests that define proper mitigations
5. Update this README with the new CVE information

## Test Categories

Security tests are organized into categories:

- **Path Traversal**: Tests for `../` exploitation
- **Absolute Path Injection**: Tests for absolute path vulnerabilities
- **Symlink Following**: Tests for symlink-based attacks
- **TOCTOU**: Time-of-Check-Time-of-Use race conditions
- **Configuration Injection**: Tests for malicious configuration
- **Permission Issues**: Tests for privilege escalation concerns

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
