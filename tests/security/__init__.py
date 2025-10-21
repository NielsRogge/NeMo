# Copyright (c) 2025, NVIDIA CORPORATION.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Security Test Suite for NeMo Framework

This package contains security-focused tests that verify and document
security vulnerabilities in the NeMo framework. These tests are designed to:

1. Verify the presence of known security vulnerabilities
2. Document attack vectors and exploitation techniques
3. Provide regression tests after vulnerabilities are fixed
4. Demonstrate proper security validation requirements

IMPORTANT: These tests document CRITICAL security vulnerabilities.
They are designed to FAIL if the vulnerabilities are not present,
meaning a passing test indicates a security issue exists.

Test Organization:
- test_cve_004_path_traversal.py: Path traversal vulnerability tests
"""
