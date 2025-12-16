# Version Management

This document explains how version information is managed in LivingArchive-Kage-pro.

## Version Sources

The system checks for version information in the following order:

1. **`ryu_app/version.py`** - Primary source for version number
2. **Git tags** - If a git tag exists, it's used as the version
3. **Git commit hash** - Fallback if no tag or version.py exists

## Updating Version

### Method 1: Update version.py (Recommended)

Edit `ryu_app/version.py`:

```python
__version__ = "0.2.0"
__version_info__ = (0, 2, 0)
```

### Method 2: Create a Git Tag

```bash
git tag -a v0.2.0 -m "Release version 0.2.0"
git push origin v0.2.0
```

### Method 3: Automatic Versioning (CI/CD)

You can set `__git_commit__` and `__build_date__` during build:

```python
# In version.py or build script
__git_commit__ = os.environ.get('GIT_COMMIT', None)
__build_date__ = datetime.now().isoformat()
```

## Viewing Version

The version is displayed on the Settings page at:
- `http://127.0.0.1:9000/reconnaissance/settings/`

The page shows:
- Current Version (from version.py, git tag, or commit)
- Current Commit (git commit hash)
- Git Branch (current branch name)
- Repository link

## Version Format

Follow [Semantic Versioning](https://semver.org/):
- **MAJOR.MINOR.PATCH** (e.g., 1.2.3)
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

## Example Workflow

1. Make changes and commit:
   ```bash
   git add .
   git commit -m "Add new feature"
   ```

2. Update version in `ryu_app/version.py`:
   ```python
   __version__ = "0.2.0"
   ```

3. Create a release tag:
   ```bash
   git tag -a v0.2.0 -m "Release 0.2.0"
   git push origin v0.2.0
   ```

4. The Settings page will now show version 0.2.0

