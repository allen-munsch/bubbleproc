#!/bin/bash
set -eo pipefail
export BUBBLEPROC_DEBUG=true
# --- Setup ---
echo "⚙️  Setting up test environment..."
# Create a dummy file that should only be visible when explicitly allowed
touch /tmp/test_file_host.txt
echo "HOST_SECRET" > /tmp/test_file_host.txt

# --- Test 1: System Write Protection (Attempt to write to /usr/bin) ---
echo "--- Test 1: System Write Protection (Attempt to write to /usr/bin) ---"
# Expected: Command should fail with a non-zero exit code due to read-only /usr mount.
if bubbleproc -- /bin/bash -c 'touch /usr/bin/test_file'; then
    echo "❌ FAILED: System write protection did not block writing to /usr/bin."
    exit 1
fi
echo "✅ Passed: System write blocked writing to /usr/bin."

# --- Test 2: Network Isolation (Default Safe Mode) ---
echo "--- Test 2: Network Isolation (Default) ---"
# Expected: curl fails because network is blocked by default (--unshare-net).
if bubbleproc -- curl -s https://www.google.com >/dev/null 2>&1; then
    echo "❌ FAILED: Network access was not blocked by default."
    exit 1
fi
echo "✅ Passed: Network access is blocked by default."

# --- Test 3: Secret File Isolation (Default Safe Mode) ---
echo "--- Test 3: Secret File Isolation (Default) ---"
# Expected: $HOME is unmounted or empty, so the secret key should not be found.
# The Docker user 'bubbleuser' has a secret in /home/bubbleuser/.ssh/id_rsa
SECRET_PATH="$HOME/.ssh/id_rsa"
if bubbleproc -- cat "$SECRET_PATH" >/dev/null 2>&1; then
    echo "❌ FAILED: Secret key was exposed despite default safe settings."
    exit 1
fi
echo "✅ Passed: Secret key is not exposed by default."

# --- Test 4: Secret File Isolation (Share Home Mode) ---
echo "--- Test 4: Secret File Isolation (Share Home, Secrets Blocked) ---"
# Expected: $HOME is shared, but the .ssh secret path is explicitly tmpfs-overlaid.
if bubbleproc --share-home -- cat "$SECRET_PATH" >/dev/null 2>&1; then
    echo "❌ FAILED: Secret was exposed in --share-home mode (overlay failed)."
    exit 1
fi
echo "✅ Passed: Secret is correctly blocked in --share-home mode."

# --- Test 5: Explicit Read/Write Mount (Validation) ---
echo "--- Test 5: Explicit Read/Write Mount ---"
# Expected: Should be able to read and write to /tmp, which is bound as tmpfs.
# We also test explicit binding of the host's /tmp/test_file_host.txt (rw is not needed)
OUTPUT=$(bubbleproc --ro /tmp/test_file_host.txt -- /bin/bash -c "cat /tmp/test_file_host.txt")
if [[ "$OUTPUT" != *'HOST_SECRET'* ]]; then
    echo "❌ FAILED: Explicit read-only mount failed."
    exit 1
fi
echo "✅ Passed: Explicit read-only mount succeeded."


echo -e "\n🎉 ALL SECURITY TESTS PASSED! bubbleproc is confirmed to enforce isolation."
