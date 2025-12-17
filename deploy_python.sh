#!/bin/bash
set -euo pipefail

# ============================================================================
# deploy_python.sh - Build and publish bubbleproc Python package to PyPI
# ============================================================================
#
# Usage:
#   ./deploy_python.sh              # Build and upload to PyPI
#   ./deploy_python.sh --test       # Build and upload to TestPyPI
#   ./deploy_python.sh --build-only # Build without uploading
#   ./deploy_python.sh --help       # Show help
#
# Environment variables:
#   TWINE_USERNAME    - PyPI username (or use __token__ for API tokens)
#   TWINE_PASSWORD    - PyPI password or API token
#   MATURIN_PYPI_TOKEN - Alternative: maturin can publish directly with this
#
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BINDINGS_DIR="${SCRIPT_DIR}/bindings/python"
DIST_DIR="${PYTHON_BINDINGS_DIR}/dist"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Defaults
UPLOAD_TARGET="pypi"
BUILD_ONLY=false
SKIP_TESTS=false
VERBOSE=false

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Build and publish the bubbleproc Python package to PyPI.

Options:
    --test          Upload to TestPyPI instead of PyPI
    --build-only    Build the package without uploading
    --skip-tests    Skip running tests before publishing
    --verbose       Show verbose output
    --help          Show this help message

Environment Variables:
    TWINE_USERNAME      PyPI username (use '__token__' for API tokens)
    TWINE_PASSWORD      PyPI password or API token
    
    For TestPyPI, you can also set:
    TWINE_TEST_USERNAME
    TWINE_TEST_PASSWORD

Examples:
    # Build and upload to PyPI using environment variables
    export TWINE_USERNAME=__token__
    export TWINE_PASSWORD=pypi-xxxxx
    ./deploy_python.sh

    # Build and upload to TestPyPI
    ./deploy_python.sh --test

    # Just build, don't upload
    ./deploy_python.sh --build-only

EOF
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is required but not installed."
        return 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing=()
    
    # Required: Python
    if ! check_command python3; then
        missing+=("python3")
    fi
    
    # Required: Rust/Cargo (for maturin)
    if ! check_command cargo; then
        missing+=("cargo (Rust)")
    fi
    
    # Required: maturin
    if ! check_command maturin; then
        log_warn "maturin not found. Installing..."
        pip install maturin || {
            log_error "Failed to install maturin"
            missing+=("maturin")
        }
    fi
    
    # Required for upload: twine
    if [[ "$BUILD_ONLY" == false ]]; then
        if ! check_command twine; then
            log_warn "twine not found. Installing..."
            pip install twine || {
                log_error "Failed to install twine"
                missing+=("twine")
            }
        fi
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_error "Please install them and try again."
        exit 1
    fi
    
    log_success "All dependencies satisfied"
}

check_credentials() {
    if [[ "$BUILD_ONLY" == true ]]; then
        return 0
    fi
    
    log_info "Checking PyPI credentials..."
    
    if [[ "$UPLOAD_TARGET" == "testpypi" ]]; then
        # Check for TestPyPI credentials
        if [[ -z "${TWINE_TEST_USERNAME:-}" ]] && [[ -z "${TWINE_USERNAME:-}" ]]; then
            log_error "No PyPI credentials found."
            log_error "Set TWINE_USERNAME and TWINE_PASSWORD environment variables."
            log_error "For API tokens, use TWINE_USERNAME=__token__"
            exit 1
        fi
    else
        # Check for PyPI credentials
        if [[ -z "${TWINE_USERNAME:-}" ]]; then
            log_error "No PyPI credentials found."
            log_error "Set TWINE_USERNAME and TWINE_PASSWORD environment variables."
            log_error "For API tokens, use TWINE_USERNAME=__token__"
            exit 1
        fi
    fi
    
    log_success "Credentials configured"
}

clean_dist() {
    log_info "Cleaning previous builds..."
    
    if [[ -d "$DIST_DIR" ]]; then
        rm -rf "$DIST_DIR"
        log_info "Removed $DIST_DIR"
    fi
    
    # Also clean any wheel files in the bindings directory
    find "$PYTHON_BINDINGS_DIR" -name "*.whl" -delete 2>/dev/null || true
    find "$PYTHON_BINDINGS_DIR" -name "*.tar.gz" -delete 2>/dev/null || true
    
    log_success "Clean complete"
}

run_tests() {
    if [[ "$SKIP_TESTS" == true ]]; then
        log_warn "Skipping tests (--skip-tests flag)"
        return 0
    fi
    
    log_info "Running tests..."
    
    # Check if we're in a Docker-capable environment or have bwrap
    if command -v bwrap &> /dev/null; then
        log_info "Running Python API tests..."
        cd "$SCRIPT_DIR"
        
        # Build a test wheel first
        cd "$PYTHON_BINDINGS_DIR"
        maturin build --release
        
        # Install the wheel in a temp environment
        local test_wheel=$(find "$DIST_DIR" -name "*.whl" | head -1)
        if [[ -n "$test_wheel" ]]; then
            pip install "$test_wheel" --force-reinstall --quiet
            
            cd "$SCRIPT_DIR"
            if python3 test_python_api.py; then
                log_success "Tests passed"
            else
                log_error "Tests failed"
                exit 1
            fi
        else
            log_warn "No wheel found for testing, skipping..."
        fi
    else
        log_warn "bwrap not found - skipping integration tests"
        log_warn "Tests require bubblewrap to be installed"
    fi
}

build_package() {
    log_info "Building Python package with maturin..."
    
    cd "$PYTHON_BINDINGS_DIR"
    
    # Ensure dist directory exists
    mkdir -p "$DIST_DIR"
    
    # Build for current platform
    local maturin_args=(
        "build"
        "--release"
        "--out" "$DIST_DIR"
    )
    
    if [[ "$VERBOSE" == true ]]; then
        maturin_args+=("--verbose")
    fi
    
    log_info "Running: maturin ${maturin_args[*]}"
    
    if maturin "${maturin_args[@]}"; then
        log_success "Build complete"
        
        # Show what was built
        log_info "Built packages:"
        ls -la "$DIST_DIR"/*.whl 2>/dev/null || log_warn "No wheel files found"
        ls -la "$DIST_DIR"/*.tar.gz 2>/dev/null || true
    else
        log_error "Build failed"
        exit 1
    fi
    
    cd "$SCRIPT_DIR"
}

build_sdist() {
    log_info "Building source distribution..."
    
    cd "$PYTHON_BINDINGS_DIR"
    
    if maturin sdist --out "$DIST_DIR"; then
        log_success "Source distribution built"
    else
        log_warn "Failed to build source distribution (this is optional)"
    fi
    
    cd "$SCRIPT_DIR"
}

upload_package() {
    if [[ "$BUILD_ONLY" == true ]]; then
        log_info "Build-only mode, skipping upload"
        log_success "Package built successfully in: $DIST_DIR"
        return 0
    fi
    
    log_info "Uploading package to ${UPLOAD_TARGET}..."
    
    local twine_args=(
        "upload"
    )
    
    # Configure repository
    if [[ "$UPLOAD_TARGET" == "testpypi" ]]; then
        twine_args+=("--repository" "testpypi")
        twine_args+=("--repository-url" "https://test.pypi.org/legacy/")
        
        # Use test credentials if available
        if [[ -n "${TWINE_TEST_USERNAME:-}" ]]; then
            twine_args+=("--username" "${TWINE_TEST_USERNAME}")
        fi
        if [[ -n "${TWINE_TEST_PASSWORD:-}" ]]; then
            twine_args+=("--password" "${TWINE_TEST_PASSWORD}")
        fi
    fi
    
    if [[ "$VERBOSE" == true ]]; then
        twine_args+=("--verbose")
    fi
    
    # Add all distribution files
    twine_args+=("${DIST_DIR}/"*)
    
    log_info "Running: twine ${twine_args[*]/%password*/password=***}"
    
    if twine "${twine_args[@]}"; then
        log_success "Upload complete!"
        
        if [[ "$UPLOAD_TARGET" == "testpypi" ]]; then
            echo ""
            log_info "Package uploaded to TestPyPI"
            log_info "Install with: pip install --index-url https://test.pypi.org/simple/ bubbleproc"
        else
            echo ""
            log_info "Package uploaded to PyPI"
            log_info "Install with: pip install bubbleproc"
        fi
    else
        log_error "Upload failed"
        exit 1
    fi
}

verify_package() {
    log_info "Verifying package with twine check..."
    
    if twine check "${DIST_DIR}/"*; then
        log_success "Package verification passed"
    else
        log_warn "Package verification had warnings (upload may still work)"
    fi
}

show_summary() {
    echo ""
    echo "=========================================="
    echo "        Deployment Summary"
    echo "=========================================="
    echo ""
    echo "Package directory: $PYTHON_BINDINGS_DIR"
    echo "Distribution directory: $DIST_DIR"
    echo ""
    echo "Built files:"
    ls -1 "$DIST_DIR"/ 2>/dev/null | sed 's/^/  - /'
    echo ""
    
    if [[ "$BUILD_ONLY" == true ]]; then
        echo "Mode: Build only (no upload)"
    else
        echo "Target: $UPLOAD_TARGET"
    fi
    echo ""
}

# ============================================================================
# Main Script
# ============================================================================

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --test)
                UPLOAD_TARGET="testpypi"
                shift
                ;;
            --build-only)
                BUILD_ONLY=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    echo ""
    echo "=========================================="
    echo "  bubbleproc Python Package Deployment"
    echo "=========================================="
    echo ""
    
    # Verify we're in the right directory
    if [[ ! -d "$PYTHON_BINDINGS_DIR" ]]; then
        log_error "Cannot find Python bindings directory: $PYTHON_BINDINGS_DIR"
        log_error "Please run this script from the project root"
        exit 1
    fi
    
    # Run deployment steps
    check_dependencies
    check_credentials
    clean_dist
    run_tests
    build_package
    build_sdist
    verify_package
    upload_package
    show_summary
    
    log_success "Deployment complete!"
}

# Run main function
main "$@"
