#!/usr/bin/env bash
#
# install.sh - copy the modules in ./modules/ into ~/.nxc/modules so `nxc -M <name>`
# finds them, then check each one loads under the protocol it declares.
#
# nxc loads all user modules from one directory; each module's supported_protocols
# decides which `nxc <proto> -L` listing it shows up in, so we verify against the right
# protocol. Safe to re-run. Override the target dir with NXC_MODULES_DIR:
#
#     ./install.sh
#     NXC_MODULES_DIR=/opt/nxc/modules ./install.sh
#
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/modules" && pwd)"
DEST="${NXC_MODULES_DIR:-$HOME/.nxc/modules}"

echo "[*] source : $SRC"
echo "[*] target : $DEST"

NXC="$(command -v nxc || command -v netexec || true)"
if [ -n "$NXC" ]; then
    echo "[*] netexec: $NXC ($("$NXC" --version 2>/dev/null | head -1))"
else
    echo "[!] nxc/netexec not on PATH - installing anyway; modules will work once it is."
fi

# Read a module's supported_protocols straight from its source (AST, no import/side effects).
# Prints them space-separated, e.g. "ldap" or "smb ldap"; empty if it can't be determined.
module_protocols() {
    python3 - "$1" <<'PY' 2>/dev/null || true
import ast, sys
tree = ast.parse(open(sys.argv[1]).read())
for node in ast.walk(tree):
    if isinstance(node, ast.ClassDef) and node.name == "NXCModule":
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "supported_protocols" for t in stmt.targets
            ):
                try:
                    print(" ".join(str(p) for p in ast.literal_eval(stmt.value)))
                except Exception:
                    pass
PY
}

mkdir -p "$DEST"

shopt -s nullglob
mods=("$SRC"/*.py)
[ ${#mods[@]} -gt 0 ] || { echo "[!] no .py modules found in $SRC" >&2; exit 1; }

names=()
protos=()   # parallel to names[]: space-separated protocols for each installed module
for m in "${mods[@]}"; do
    base="$(basename "$m")"
    # best-effort syntax check (no import, no .pyc written)
    if command -v python3 >/dev/null 2>&1 && \
       ! python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$m" 2>/dev/null; then
        echo "[-] $base has a SYNTAX ERROR - skipping"
        continue
    fi

    p="$(module_protocols "$m")"
    if [ -z "$p" ]; then
        echo "[!] $base: could not read supported_protocols - will verify against smb+ldap"
        p="smb ldap"
    fi

    cp -f "$m" "$DEST/"
    echo "[+] installed $base (${p// /, })"
    names+=("${base%.py}")
    protos+=("$p")
done
echo "[*] ${#names[@]} module(s) installed into $DEST"

# Verify nxc actually loads each module UNDER ITS OWN PROTOCOL (a module only appears
# in `nxc <proto> -L` for a protocol it declares). Cache each protocol's listing so we
# run `nxc <proto> -L` at most once per protocol.
if [ -n "$NXC" ] && [ ${#names[@]} -gt 0 ]; then
    echo "[*] verifying each module against its declared protocol(s):"
    declare -A LISTING
    for i in "${!names[@]}"; do
        n="${names[$i]}"
        loaded_in=()
        missing_in=()
        for proto in ${protos[$i]}; do
            if [ -z "${LISTING[$proto]+x}" ]; then
                LISTING[$proto]="$("$NXC" "$proto" -L 2>/dev/null || true)"
            fi
            if printf '%s\n' "${LISTING[$proto]}" | grep -qE "\b${n}\b"; then
                loaded_in+=("$proto")
            else
                missing_in+=("$proto")
            fi
        done

        if [ ${#missing_in[@]} -eq 0 ]; then
            echo "    [+] $n loaded (${loaded_in[*]})"
        else
            echo "    [-] $n NOT listed under: ${missing_in[*]} - inspect: $NXC ${missing_in[0]} -M $n --options"
        fi
    done
fi
