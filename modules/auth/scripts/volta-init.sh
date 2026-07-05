#!/usr/bin/env bash
#
# Pin Node.js and npm for picketlink-auth / angular-auth-ui using Volta.
# Versions are read from angular-auth-ui/.nvmrc and package.json packageManager,
# matching frontend-maven-plugin settings in pom.xml.
#
# Usage:
#   ./scripts/volta-init.sh
#   source ./scripts/volta-init.sh   # also exports Volta shims into current shell
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTH_MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
UI_DIR="${AUTH_MODULE_DIR}/angular-auth-ui"
NVMRC_FILE="${UI_DIR}/.nvmrc"
PACKAGE_JSON="${UI_DIR}/package.json"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--install-volta]

Ensures Volta pins the Node/npm toolchain for angular-auth-ui:
  - Node:  from angular-auth-ui/.nvmrc (currently aligned with pom.xml node.version)
  - npm:   from angular-auth-ui/package.json packageManager field

Options:
  --install-volta   Install Volta via https://volta.sh when it is not present
EOF
}

ensure_volta() {
  if command -v volta >/dev/null 2>&1; then
    return 0
  fi

  if [[ "${1:-}" == "--install-volta" ]]; then
    echo "Volta not found; installing from https://get.volta.sh ..."
    curl -fsSL https://get.volta.sh | bash
    export VOLTA_HOME="${VOLTA_HOME:-${HOME}/.volta}"
    export PATH="${VOLTA_HOME}/bin:${PATH}"
  fi

  if ! command -v volta >/dev/null 2>&1; then
    echo "error: Volta is required. Install from https://volta.sh or re-run with --install-volta" >&2
    exit 1
  fi
}

read_node_version() {
  if [[ ! -f "${NVMRC_FILE}" ]]; then
    echo "error: missing ${NVMRC_FILE}" >&2
    exit 1
  fi
  tr -d '[:space:]' < "${NVMRC_FILE}"
}

read_npm_version() {
  if [[ ! -f "${PACKAGE_JSON}" ]]; then
    echo "error: missing ${PACKAGE_JSON}" >&2
    exit 1
  fi

  local package_manager
  package_manager="$(sed -n 's/^[[:space:]]*"packageManager"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${PACKAGE_JSON}")"
  if [[ -z "${package_manager}" ]]; then
    echo "error: packageManager not found in ${PACKAGE_JSON}" >&2
    exit 1
  fi

  case "${package_manager}" in
    npm@*)
      echo "${package_manager#npm@}"
      ;;
    *)
      echo "error: unsupported packageManager '${package_manager}' (expected npm@x.y.z)" >&2
      exit 1
      ;;
  esac
}

pin_toolchain() {
  local node_version="$1"
  local npm_version="$2"

  echo "Pinning toolchain in ${UI_DIR}"
  echo "  node@${node_version}"
  echo "  npm@${npm_version}"

  cd "${UI_DIR}"
  volta install "node@${node_version}"
  volta install "npm@${npm_version}"
  volta pin "node@${node_version}"
  volta pin "npm@${npm_version}"
}

verify_toolchain() {
  cd "${UI_DIR}"
  echo
  echo "Active toolchain (via Volta):"
  echo "  node: $(node -v) (${VOLTA_NODE:-pinned})"
  echo "  npm:  $(npm -v) (${VOLTA_NPM:-pinned})"
  echo
  echo "Run UI commands from ${UI_DIR}, for example:"
  echo "  cd ${UI_DIR} && npm install && npm run build"
}

main() {
  local install_flag=""
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
  fi
  if [[ "${1:-}" == "--install-volta" ]]; then
    install_flag="--install-volta"
  elif [[ -n "${1:-}" ]]; then
    echo "error: unknown argument '$1'" >&2
    usage >&2
    exit 1
  fi

  ensure_volta "${install_flag}"

  local node_version npm_version
  node_version="$(read_node_version)"
  npm_version="$(read_npm_version)"

  pin_toolchain "${node_version}" "${npm_version}"
  verify_toolchain
}

main "$@"
