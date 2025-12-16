"""
Version information for LivingArchive-Kage-pro
This file can be updated during releases or automatically via CI/CD
"""
__version__ = "0.1.0"
__version_info__ = (0, 1, 0)
__build_date__ = None  # Can be set during build
__git_commit__ = None  # Can be set during build

def get_version():
    """Get the current version string"""
    return __version__

def get_version_info():
    """Get version as tuple"""
    return __version_info__

def get_full_version():
    """Get full version string with commit if available"""
    version = __version__
    if __git_commit__:
        version += f" (commit: {__git_commit__})"
    if __build_date__:
        version += f" (built: {__build_date__})"
    return version

