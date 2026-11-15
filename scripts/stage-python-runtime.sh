#!/bin/bash
set -euo pipefail

# scripts/stage-python-runtime.sh
# Staging script for portable arm64 Python 3.11 and OSINT tools

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RESOURCES_DIR="$ROOT_DIR/resources"
PY_DIR="$RESOURCES_DIR/python"
SF_DIR="$RESOURCES_DIR/spiderfoot"

PYTHON_TARBALL_URL="https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.11.18%2B20261026-aarch64-apple-darwin-install_only_stripped.tar.gz"

echo "=== Staging Portable arm64 Python Environment ==="

mkdir -p "$RESOURCES_DIR"

# 1. Download and unpack Astral Python 3.11 if not present
if [ ! -f "$PY_DIR/bin/python3" ]; then
  echo "[1/5] Downloading Astral CPython 3.11 arm64..."
  TMP_TAR="/tmp/cpython-arm64-staging-$$.tar.gz"
  curl -sL "$PYTHON_TARBALL_URL" -o "$TMP_TAR"
  echo "Extracting runtime to $PY_DIR..."
  rm -rf "$PY_DIR"
  mkdir -p "$PY_DIR"
  tar -xzf "$TMP_TAR" -C "$RESOURCES_DIR"
  rm -f "$TMP_TAR"
else
  echo "[1/5] Python runtime already present at $PY_DIR."
fi

# 2. Stage SpiderFoot Engine
echo "[2/5] Staging SpiderFoot engine..."
rm -rf "$SF_DIR"
mkdir -p "$SF_DIR"
SF_SOURCE="${SPIDERFOOT_SOURCE:-$HOME/osint-perso/spiderfoot}"
if [ -d "$SF_SOURCE" ]; then
  rsync -av \
    --exclude='.git' \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='test' \
    --exclude='docs' \
    --exclude='Dockerfile*' \
    --exclude='docker-compose*' \
    "$SF_SOURCE/" "$SF_DIR/" > /dev/null
else
  echo "WARNING: Host SpiderFoot source not found at $SF_SOURCE"
fi

# 3. Install packages into embedded site-packages
echo "[3/5] Installing OSINT tools into embedded site-packages..."
PIP="$PY_DIR/bin/pip3"

# Install maigret pinned to avoid pip backtracking
"$PIP" install --no-cache-dir "maigret==0.6.6"

# Install remaining core tools and spiderfoot requirements
"$PIP" install --no-cache-dir \
  "holehe==1.61" \
  "ignorant==1.2" \
  "h8mail==2.5.6" \
  "ghunt==2.3.4" \
  -r "$SF_DIR/requirements.txt"

# Ensure lxml>=6.0.2 is installed for full Maigret & SpiderFoot compatibility
"$PIP" install --no-cache-dir "lxml>=6.0.2"

# 4. Create POSIX Wrapper Scripts
echo "[4/5] Creating POSIX wrapper scripts in $PY_DIR/bin/..."

cat << 'EOF' > "$PY_DIR/bin/holehe"
#!/bin/sh
DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$DIR/python3"
export PYTHONHOME="$(cd "$DIR/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export SSL_CERT_FILE="$DIR/../lib/python3.11/site-packages/certifi/cacert.pem"
exec "$PYTHON" -c "import sys; sys.argv[0] = '$0'; from holehe.core import main; sys.exit(main())" "$@"
EOF

cat << 'EOF' > "$PY_DIR/bin/maigret"
#!/bin/sh
DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$DIR/python3"
export PYTHONHOME="$(cd "$DIR/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export SSL_CERT_FILE="$DIR/../lib/python3.11/site-packages/certifi/cacert.pem"
exec "$PYTHON" -c "import sys; sys.argv[0] = '$0'; from maigret.maigret import run; sys.exit(run())" "$@"
EOF

cat << 'EOF' > "$PY_DIR/bin/ignorant"
#!/bin/sh
DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$DIR/python3"
export PYTHONHOME="$(cd "$DIR/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export SSL_CERT_FILE="$DIR/../lib/python3.11/site-packages/certifi/cacert.pem"
exec "$PYTHON" -c "import sys; sys.argv[0] = '$0'; from ignorant.core import main; sys.exit(main())" "$@"
EOF

cat << 'EOF' > "$PY_DIR/bin/h8mail"
#!/bin/sh
DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$DIR/python3"
export PYTHONHOME="$(cd "$DIR/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export SSL_CERT_FILE="$DIR/../lib/python3.11/site-packages/certifi/cacert.pem"
exec "$PYTHON" -c "import sys; sys.argv[0] = '$0'; from h8mail.__main__ import main; sys.exit(main())" "$@"
EOF

cat << 'EOF' > "$PY_DIR/bin/ghunt"
#!/bin/sh
DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$DIR/python3"
export PYTHONHOME="$(cd "$DIR/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export SSL_CERT_FILE="$DIR/../lib/python3.11/site-packages/certifi/cacert.pem"
exec "$PYTHON" -c "import sys; sys.argv[0] = '$0'; from ghunt.ghunt import main; sys.exit(main())" "$@"
EOF

cat << 'EOF' > "$PY_DIR/bin/spiderfoot"
#!/bin/sh
DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$DIR/python3"
export PYTHONHOME="$(cd "$DIR/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export SSL_CERT_FILE="$DIR/../lib/python3.11/site-packages/certifi/cacert.pem"

if [ -d "$DIR/../../spiderfoot" ]; then
  SF_DIR="$(cd "$DIR/../../spiderfoot" && pwd)"
elif [ -d "$DIR/../spiderfoot" ]; then
  SF_DIR="$(cd "$DIR/../spiderfoot" && pwd)"
elif [ -d "$DIR/../../../resources/spiderfoot" ]; then
  SF_DIR="$(cd "$DIR/../../../resources/spiderfoot" && pwd)"
else
  SF_DIR="$DIR/spiderfoot"
fi

export PYTHONPATH="$SF_DIR:$DIR/../lib/python3.11/site-packages${PYTHONPATH:+:$PYTHONPATH}"
cd "$SF_DIR" || exit 1
if [ "$1" = "sf.py" ]; then
  shift
fi
exec "$PYTHON" "$SF_DIR/sf.py" "$@"
EOF

chmod 0755 "$PY_DIR/bin"/{holehe,maigret,ignorant,h8mail,ghunt,spiderfoot}
if [ -f "$SF_DIR/sf.py" ]; then
  chmod 0755 "$SF_DIR/sf.py"
fi

# 5. Anonymity Scrubbing and Verification
echo "[5/5] Performing anonymity sanitation..."
# Remove non-essential pip generated CLI scripts from bin
for f in "$PY_DIR/bin"/*; do
  base="$(basename "$f")"
  case "$base" in
    python*|pip*|2to3*|idle3*|pydoc3*|holehe|maigret|ignorant|h8mail|ghunt|spiderfoot)
      ;;
    *)
      rm -f "$f"
      ;;
  esac
done

find "$PY_DIR" "$SF_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$PY_DIR" "$SF_DIR" -name "*.pyc" -delete 2>/dev/null || true
find "$PY_DIR" -name "direct_url.json" -delete 2>/dev/null || true
rm -rf "$PY_DIR/lib/python3.11/site-packages/pip/_vendor/distlib"/*.exe 2>/dev/null || true

# Assert certifi cacert.pem exists
if [ ! -f "$PY_DIR/lib/python3.11/site-packages/certifi/cacert.pem" ]; then
  echo "ERROR: certifi cacert.pem is missing!" >&2
  exit 1
fi

echo "=== Portable arm64 Python Environment Staging Complete ==="
