# Security Tests: CVE-008 - Arbitrary File Write

## Summary

This PR adds comprehensive security tests to verify and document the arbitrary file write vulnerability described in CVE-008.

## Details

**CVE ID**: CVE-008  
**Title**: [CVE-008] Arbitrary File Write  
**Severity**: CRITICAL  
**Jira Issue**: https://ml6team.atlassian.net/browse/DR-138

## Vulnerability Description

The application may be vulnerable to arbitrary file writes. The framework saves model checkpoints, logs, and processed data. If the output paths for these files can be controlled by a user or a malicious configuration, it could allow an attacker to overwrite critical system files or write malicious scripts (e.g., web shells) to sensitive locations.

A `grep` search found numerous instances of file write operations using `open(..., 'w')`, `open(..., 'wb')`, and `.write_text()`. For example:
- `/tools/nemo_forced_aligner/align.py:329: f_manifest_out = open(tgt_manifest_filepath, 'w')`
- `/nemo/export/multimodal/build.py:290: with open(engine_file, 'wb') as f:`
- `/nemo/core/classes/mixins/hf_io_mixin.py:229: model_card_filepath.write_text(str(model_card), encoding='utf-8', errors='ignore')`

These are not vulnerabilities in themselves, but they highlight the need to ensure that file paths are not controllable by external input in a way that would allow writing to arbitrary locations.

## Solution Design

- Review all file write operations to identify any instances where the file path can be influenced by user input or external configuration.
- Implement strict validation on all file paths to prevent directory traversal and writing to unintended locations.
- Use a whitelist of allowed directories for file writes.
- Run the application with the least privilege necessary to limit the impact of a potential file write vulnerability.

## Acceptance Criteria

- A thorough review of all file write operations has been completed.
- All potential arbitrary file write vulnerabilities have been remediated.
- The application is confirmed to not be vulnerable to arbitrary file write attacks.

## Tests Added

This PR adds comprehensive security tests in `tests/security/test_cve_008_arbitrary_file_write.py`:

### Test Classes

1. **TestCVE008DirectoryTraversal** - Tests for directory traversal attacks using `../` sequences
2. **TestCVE008AbsolutePathInjection** - Tests for absolute path injection in file writes  
3. **TestCVE008ConfigurationControlled** - Tests for config-controlled file paths
4. **TestCVE008PickleFileWrite** - Tests for pickle file write vulnerabilities (particularly dangerous)
5. **TestCVE008DatasetOutputFile** - Tests for dataset output file vulnerabilities
6. **TestCVE008TempFileInManifest** - Tests for predictable temp file vulnerabilities
7. **TestCVE008RaceConditions** - Tests for TOCTOU (time-of-check-time-of-use) vulnerabilities
8. **TestCVE008PathNormalizationBypass** - Tests for path normalization bypass techniques
9. **TestCVE008IntegrationScenarios** - End-to-end attack scenario demonstrations

### Attack Vectors Tested

- Directory traversal: `../../etc/passwd`
- Absolute path injection: `/etc/malicious_config`
- Symlink-based attacks: Writing through symbolic links
- Configuration file overwrites
- Race conditions between makedirs and file open
- Path normalization bypasses (double encoding, mixed separators, etc.)

### Vulnerable Code Patterns

Tests verify the following patterns found in the codebase:
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

## Running the Tests

```bash
# Run all security tests
pytest tests/security/ -v

# Run only CVE-008 tests
pytest -m cve_008 -v

# Run specific test class
pytest tests/security/test_cve_008_arbitrary_file_write.py::TestCVE008DirectoryTraversal -v
```

## Important Notes

⚠️ **These tests verify that the vulnerability exists. They do NOT fix the vulnerability.**

The purpose of these tests is to:
1. Document the vulnerability with concrete test cases
2. Verify the presence of the vulnerability before fixes are applied
3. Provide validation tests for when fixes are implemented
4. Prevent regression after the vulnerability is fixed

## Related Issues

- **Jira**: https://ml6team.atlassian.net/browse/DR-138
- **CVE**: CVE-008

## Documentation

Added comprehensive documentation in `tests/security/README.md` covering:
- Purpose and organization of security tests
- Detailed description of CVE-008
- Instructions for running tests
- Contributing guidelines for security tests
- Security disclosure guidelines
