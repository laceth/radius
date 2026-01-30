#!/bin/bash
# Generate requirements files into requirements.txt and requirements-dev.txt from pyproject.toml
# Only run this script when dependencies changed in pyproject.toml

echo "🔄 Generating requirements files from pyproject.toml..."

# Check if pip-tools is installed
if ! command -v pip-compile &> /dev/null; then
    echo "📦 Installing pip-tools..."
    pip install pip-tools
fi

# Generate requirements.txt (production dependencies only)
echo "📝 Generating requirements.txt..."
pip-compile pyproject.toml --output-file requirements.txt

# Generate requirements-dev.txt (with dev dependencies)
echo "📝 Generating requirements-dev.txt..."
pip-compile --extra dev pyproject.toml --output-file requirements-dev.txt

echo "✅ All requirements files updated!"
echo ""
echo "Generated files:"
echo "  - requirements.txt (production)"
echo "  - requirements-dev.txt (development)"
echo ""
echo "📋 What to do next:"
echo ""
echo "🆕 If you're setting up for the first time:"
echo "     pip install -r requirements.txt"
echo "     ./setup-dev.sh"
echo "     (First install main libraries, then setup development tools)"
echo ""
echo "🔄 If you're updating your existing setup:"
echo "     pip install -r requirements.txt"
echo "     pip install -r requirements-dev.txt"
echo ""
echo "💡 What these files contain:"
echo "   • requirements.txt = Main libraries needed to run the code"
echo "   • requirements-dev.txt = Extra tools for code formatting and quality checks"
