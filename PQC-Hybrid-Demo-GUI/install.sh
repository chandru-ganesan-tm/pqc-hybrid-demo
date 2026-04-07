#!/usr/bin/env bash
set -euo pipefail

echo "Installing dependencies for PQC Hybrid Key Exchange Demo..."

if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed."
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "  Fedora/RHEL:   sudo dnf install python3 python3-pip"
    echo "  Arch:          sudo pacman -S python python-pip"
    exit 1
fi

NEED_PYSIDE=0
python3 -c "import PySide6" 2>/dev/null || NEED_PYSIDE=1

if [ "$NEED_PYSIDE" -eq 0 ]; then
    echo "PySide6 already installed — nothing to do."
    echo "Run the app with: ./run.sh"
    exit 0
fi

# Try system package manager first (no venv needed)
if command -v apt &> /dev/null; then
    echo "Detected Debian/Ubuntu. Installing PySide6 via apt..."
    if sudo apt install -y python3-pyside6.qtwidgets python3-pyside6.qtcore \
                           python3-pyside6.qtgui python3-pyside6.qtsvg 2>/dev/null; then
        echo ""
        echo "Done. Run: ./run.sh"
        exit 0
    fi
    echo "apt failed, falling back to pip..."
elif command -v dnf &> /dev/null; then
    echo "Detected Fedora/RHEL. Installing PySide6 via dnf..."
    if sudo dnf install -y python3-pyside6 2>/dev/null; then
        echo ""
        echo "Done. Run: ./run.sh"
        exit 0
    fi
    echo "dnf failed, falling back to pip..."
fi

# Pip fallback
echo "Installing PySide6 via pip..."
if python3 -m pip install --user PySide6 2>/dev/null; then
    echo ""
    echo "Done. Run: ./run.sh"
elif python3 -m pip install --user --break-system-packages PySide6; then
    echo ""
    echo "Done. Run: ./run.sh"
else
    echo ""
    echo "Error: could not install PySide6. Try manually:"
    echo "  pip install PySide6"
    exit 1
fi
