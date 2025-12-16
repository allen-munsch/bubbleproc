#!/bin/bash
set -euo pipefail

echo "=========================================="
echo "Bubbleproc Test Suite"
echo "=========================================="

echo ""
echo "1. Building Docker test image..."
docker build --progress=plain -t bubbleproc-test .

echo ""
echo "2. Running CLI Security tests..."
docker run --rm --privileged bubbleproc-test /bin/bash -c './test_security.sh'

echo ""
echo "3. Running Python API tests..."
docker run --rm --privileged bubbleproc-test /usr/bin/python3 test_python_api.py

echo ""
echo "=========================================="
echo "🎉 ALL TESTS PASSED!"
echo "=========================================="