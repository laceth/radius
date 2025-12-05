# fstester - ForeScout Automation Testing Framework

A Python framework for automating.

## 🚀 Quick Setup

### 🆕 First Time Setup

If you're setting up the project for the first time:

```bash
# 1. Clone the repository
git clone <repository-url>
cd fstester

# 2. Create and activate virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install main libraries
pip install -r requirements.txt

# 4. Setup development tools and code formatting
# This installs requirements-dev.txt and sets up pre-commit hooks
./setup-dev.sh
```

### 🔄 Updating Your Environment

If the project dependencies requirements.txt or requirements-dev.txt have been updated:

```bash
# Update main libraries
pip install -r requirements.txt

# Update development tools
pip install -r requirements-dev.txt
```

## 📋 What's Included

### Main Dependencies (`requirements.txt`)
- **paramiko** - SSH connections to network devices
- **netmiko** - Network device automation library
- **pyyaml** - YAML configuration file support
- **pywinrm** - Windows Remote Management support

### Development Tools (`requirements-dev.txt`)
- **black** - Code formatter
- **isort** - Import organizer
- **ruff** - Fast Python linter
- **mypy** - Type checker
- **pre-commit** - Git hooks for code quality

## 🛠️ Development Workflow

### Code Quality (Automatic)
Once you run `./setup-dev.sh`, code formatting happens automatically:

```bash
# Just commit normally - formatting happens automatically!
git add .
git commit -m "Your changes"
```

### Manual Code Formatting
If needed, you can run formatters manually:

```bash
# Format Python code
black .

# Organize imports
isort .

# Check for style issues
ruff check

# Run all formatting
pre-commit run --all-files
```

## 🏗️ Project Structure

```
fstester/
├── framework/          # Core framework code
├── lib/               # Library modules
│   ├── ca/           # Certificate Authority modules
│   ├── plugin/       # Plugin modules (RADIUS, etc.)
│   ├── switch/       # Network switch automation
│   └── passthrough/  # Remote execution modules
├── test/             # Test modules
├── config/           # Configuration files
└── web/              # Web dashboard
```

## 💡 For Maintainers

### Adding New Dependencies

1. Add dependencies to `pyproject.toml`
2. Generate updated requirements files:
   ```bash
   ./generate-requirements.sh
   ```
3. Commit the updated files

### Installation Options

```bash
# Using requirements files (current approach)
pip install -r requirements.txt

# Using pyproject.toml (modern approach)
pip install -e .                    # Main dependencies
pip install -e .[dev]               # With development tools
pip install -e .[windows]           # With Windows support
pip install -e .[dev,windows]       # Everything
```

## 🔧 Troubleshooting

### Virtual Environment Issues
```bash
# Create new virtual environment
python -m venv .venv

# Activate it
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows
```

### Pre-commit Hook Issues
```bash
# Reinstall pre-commit hooks
pre-commit install

# Run hooks manually
pre-commit run --all-files
```

### Dependency Conflicts
```bash
# Clean install
pip freeze | xargs pip uninstall -y
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## 📞 Support

For questions or issues:
1. Check this README first
2. Look at existing GitHub issues
3. Create a new issue with details about your setup and the problem

---

Happy testing! 🎉
