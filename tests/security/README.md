# Security Tests

This directory contains security vulnerability tests for the NeMo framework.

## Purpose

These tests serve to:
1. **Document** known security vulnerabilities with concrete test cases
2. **Verify** the presence of vulnerabilities before fixes are applied
3. **Validate** that security fixes properly address the vulnerabilities
4. **Prevent regression** after vulnerabilities are fixed

⚠️ **Important**: These tests verify that vulnerabilities exist. They do NOT fix the vulnerabilities themselves.

## Test Organization

### CVE-008: Arbitrary File Write Vulnerability

**File**: `test_cve_008_arbitrary_file_write.py`  
**Severity**: CRITICAL  
**Jira Issue**: https://ml6team.atlassian.net/browse/DR-138

**Vulnerability Description**:
The application may be vulnerable to arbitrary file writes. The framework saves model checkpoints, logs, and processed data. If the output paths for these files can be controlled by a user or a malicious configuration, it could allow an attacker to overwrite critical system files or write malicious scripts to sensitive locations.

**Test Classes**:

1. **TestCVE008DirectoryTraversal**
   - Tests for directory traversal attacks using `../` sequences
   - Verifies paths can escape intended directories
   - Tests include manifest output and makedirs operations

2. **TestCVE008AbsolutePathInjection**
   - Tests for absolute path injection in file writes
   - Verifies system paths can be targeted
   - Covers engine files, model cards, and other outputs

3. **TestCVE008ConfigurationControlled**
   - Tests for config-controlled file paths
   - Verifies malicious configs can specify dangerous paths
   - Covers manifest, YAML, and output file paths

4. **TestCVE008PickleFileWrite**
   - Tests for pickle file write vulnerabilities
   - Pickle files are particularly dangerous (can contain code)
   - Verifies pickle dumps to user-controlled paths

5. **TestCVE008DatasetOutputFile**
   - Tests for dataset output file vulnerabilities
   - Verifies dataset processing can write to arbitrary locations

6. **TestCVE008TempFileInManifest**
   - Tests for predictable temp file vulnerabilities
   - Verifies symlink attack potential

7. **TestCVE008RaceConditions**
   - Tests for TOCTOU (time-of-check-time-of-use) vulnerabilities
   - Verifies race conditions between makedirs and file open

8. **TestCVE008PathNormalizationBypass**
   - Tests for path normalization bypass techniques
   - Verifies various encoding tricks can bypass weak validation

9. **TestCVE008IntegrationScenarios**
   - End-to-end attack scenario tests
   - Complete exploitation demonstrations

**Vulnerable Code Patterns Tested**:
```python
# Pattern 1: Direct file write with user-controlled path
open(tgt_manifest_filepath, 'w')

# Pattern 2: Binary file write with user-controlled path  
with open(engine_file, 'wb') as f:
    f.write(data)

# Pattern 3: Path.write_text with user-controlled path
model_card_filepath.write_text(content, encoding='utf-8')

# Pattern 4: Pickle dump with user-controlled path
pkl.dump(self.embeddings, open(self._embeddings_file, 'wb'))

# Pattern 5: makedirs followed by file write
os.makedirs(cfg.output_dir, exist_ok=True)
open(tgt_manifest_filepath, 'w')
```

**Attack Vectors Tested**:
- Directory traversal: `../../etc/passwd`
- Absolute path injection: `/etc/malicious_config`
- Symlink-based attacks: Writing through symbolic links
- Configuration file overwrites
- Race conditions (TOCTOU)
- Path normalization bypasses

## Running the Tests

### Run all security tests:
```bash
pytest tests/security/ -v
```

### Run tests by marker:
```bash
# All security tests
pytest -m security -v

# Only CVE-008 tests
pytest -m cve_008 -v

# Only unit tests in security
pytest tests/security/ -m unit -v
```

### Run specific test class:
```bash
pytest tests/security/test_cve_008_arbitrary_file_write.py::TestCVE008DirectoryTraversal -v
```

### Run specific test:
```bash
pytest tests/security/test_cve_008_arbitrary_file_write.py::TestCVE008DirectoryTraversal::test_directory_traversal_in_manifest_output -v
```

## Test Markers

All security tests use the following markers:
- `@pytest.mark.security` - Marks test as a security test
- `@pytest.mark.cve_008` - Marks test as related to CVE-008
- `@pytest.mark.unit` - Marks test as a unit test

## Expected Behavior

### Before Fix
All tests should **PASS**, demonstrating that the vulnerabilities exist.

### After Fix
Tests should be updated or modified to verify:
1. The vulnerability is no longer exploitable
2. Proper path validation is in place
3. Directory whitelisting is enforced
4. Least privilege principles are followed

## Contributing

When adding new security tests:

1. **Create a new test file** named `test_cve_XXX_description.py`
2. **Add comprehensive documentation** in docstrings
3. **Use descriptive test names** that explain the attack vector
4. **Include vulnerability details** in test docstrings:
   - CVE ID
   - Severity
   - Jira issue link
   - Vulnerable code patterns
   - Attack vectors
5. **Add appropriate markers** (`@pytest.mark.security`, `@pytest.mark.cve_XXX`)
6. **Document expected behavior** before and after fixes

## Security Disclosure

If you discover a new vulnerability while working with these tests:

1. **Do NOT** commit the vulnerability details to public repositories
2. **Report** to the security team following responsible disclosure practices
3. **Create tests** only after coordinating with the security team
4. **Follow** the organization's security disclosure policy

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-59: Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
