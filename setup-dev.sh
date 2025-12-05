#!/bin/bash

# Development setup script for fstester
# This script installs development dependencies and sets up pre-commit hooks

set -e

echo "🚀 Setting up fstester development environment..."

# Check if we're in a virtual environment
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "⚠️  Warning: You're not in a virtual environment!"
    echo "   Consider running: python -m venv .venv && source .venv/bin/activate"
    echo ""
fi

# Install development dependencies
echo "📦 Installing development dependencies..."
if [ -f "requirements-dev.txt" ]; then
    pip install -r requirements-dev.txt
else
    echo "⚠️  requirements-dev.txt not found. Installing from pyproject.toml..."
    pip install -e .[dev]
fi

# Install pre-commit hooks
echo "🪝 Setting up pre-commit hooks..."
pre-commit install

# Run pre-commit on all files to ensure everything is formatted
echo "🔍 Running initial code formatting check..."
pre-commit run --all-files || true

echo ""
echo "✅ Setup complete! Now you can:"
echo "   • Write code normally"
echo "   • Commit changes - formatting will happen automatically"
echo "   • Run 'pre-commit run --all-files' to format all files manually"
echo "   • Run 'black .' to format Python files"
echo "   • Run 'isort .' to organize imports"
echo "   • Run 'ruff check' to check for style issues"
echo ""