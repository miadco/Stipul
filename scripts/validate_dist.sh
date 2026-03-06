#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${1:-dist}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
export PIP_DISABLE_PIP_VERSION_CHECK=1

if [[ ! -d "${DIST_DIR}" ]]; then
  echo "Distribution directory not found: ${DIST_DIR}" >&2
  exit 1
fi

wheel_path="$(ls "${DIST_DIR}"/*.whl)"
sdist_path="$(ls "${DIST_DIR}"/*.tar.gz)"
work_root="$(mktemp -d)"
trap 'rm -rf "${work_root}"' EXIT
export PIP_CACHE_DIR="${work_root}/pip-cache"

run_smoke() {
  local artifact="$1"
  local env_dir="$2"
  "${PYTHON_BIN}" -m venv --system-site-packages "${env_dir}"
  "${env_dir}/bin/python" -m pip install --no-deps --no-build-isolation "${artifact}"
  "${env_dir}/bin/agentshield" --help
  "${env_dir}/bin/agentshield" verify --help
  "${env_dir}/bin/agentshield" scan --help
  "${env_dir}/bin/python" -c "import agentshield; print(agentshield.__version__)"
}

run_smoke "${wheel_path}" "${work_root}/wheel-venv"
run_smoke "${sdist_path}" "${work_root}/sdist-venv"
