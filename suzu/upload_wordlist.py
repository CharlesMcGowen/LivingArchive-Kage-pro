#!/usr/bin/env python3
"""
Bulk upload wordlist paths to Suzu vector database.

Usage:
    python upload_wordlist.py /path/to/wordlist.txt --cms-name wordpress --wordlist-name wordpress.fuzz.txt
    python upload_wordlist.py /media/ego/328010BE80108A8D3/ego/EgoWebs1/SecLists/Discovery/Web-Content/CMS/ --recursive
"""
import os
import sys
import argparse
import logging
from pathlib import Path
from typing import List, Optional, Tuple

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
try:
    import django
    if not django.apps.apps.ready:
        django.setup()
except Exception:
    # Django might already be configured
    pass

# VectorPathStore will be imported when needed in functions

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_paths_from_file(file_path: Path) -> List[str]:
    """Load paths from a wordlist file (one per line)"""
    paths = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Ensure path starts with /
                if not line.startswith('/'):
                    line = '/' + line
                
                paths.append(line)
        
        logger.info(f"📄 Loaded {len(paths)} paths from {file_path.name}")
        return paths
    
    except Exception as e:
        logger.error(f"Error reading {file_path}: {e}")
        return []


def infer_cms_from_filename(filename: str) -> str:
    """Infer CMS name from wordlist filename"""
    filename_lower = filename.lower()
    
    cms_mappings = {
        'wordpress': ['wordpress', 'wp-'],
        'drupal': ['drupal'],
        'joomla': ['joomla'],
        'magento': ['magento'],
        'shopify': ['shopify'],
        'sitecore': ['sitecore'],
        'vbulletin': ['vbulletin', 'vb-'],
        'aem': ['aem', 'adobe'],
    }
    
    for cms_name, keywords in cms_mappings.items():
        if any(keyword in filename_lower for keyword in keywords):
            return cms_name
    
    return None


def detect_cms_for_single_path(path: str, filename_cms_hint: Optional[str] = None) -> Tuple[Optional[str], float]:
    """
    Detect CMS for a single path by analyzing its content.
    
    Args:
        path: The path string to analyze (e.g., '/wp-admin/login.php')
        filename_cms_hint: Optional CMS name from filename to use as hint/boost
    
    Returns:
        Tuple of (detected_cms, confidence_score) where:
        - detected_cms: CMS name (e.g., 'wordpress', 'drupal') or None
        - confidence_score: Confidence level (0.0-1.0)
    
    Examples:
        '/wp-admin/login.php' → ('wordpress', 0.9)  # High confidence
        '/sites/default/files/' → ('drupal', 0.8)  # High confidence
        '/admin/dashboard' → ('general', 0.3)  # Low confidence (ambiguous)
        '/api/users' → (None, 0.0)  # No CMS detected
    """
    # #region agent log
    import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B,F","location":"upload_wordlist.py:86","message":"detect_cms_for_single_path entry","data":{"path":path,"path_type":type(path).__name__,"filename_cms_hint":filename_cms_hint},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
    # #endregion
    if not path:
        result = (filename_cms_hint, 0.2) if filename_cms_hint else (None, 0.0)
        # #region agent log
        import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"F","location":"upload_wordlist.py:108","message":"Empty path, returning early","data":{"result":result},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
        # #endregion
        return result
    
    # Expanded CMS mappings with high-confidence keywords
    cms_mappings = {
        # Existing Systems
        'wordpress': ['wordpress', 'wp-admin', 'wp-content', 'wp-includes', 'wp-login.php', 'wp-config.php', 'plugins/', 'themes/', '.well-known/wps'],
        'drupal': ['drupal', 'sites/default', 'user/login', 'core/', 'modules/', 'themes/', '/node/'],
        'joomla': ['joomla', 'administrator', 'components', 'templates/', 'media/', 'index.php?option='],
        'magento': ['magento', 'admin', 'catalog', 'pub/static', 'static/version', 'frontend/', 'backend/'],
        'shopify': ['shopify', 'admin', 'themes', 'cdn.shopify.com', 'shop_assets', '/collections/', '/products/'],
        'sitecore': ['sitecore', 'sitecore/admin', '/shell/'],
        'vbulletin': ['vbulletin', 'vb-', 'admincp'],
        'aem': ['aem', 'adobe', 'crx/de', '/editor.html', '/content/dam/'],
        'aspnet': ['asp.net', '.aspx', '.asmx', 'web.config', '__viewstate'],
        'laravel': ['laravel', '/vendor/laravel', '.env', 'mix-manifest.json', '/storage/'],
        'apache': ['.htaccess', 'httpd.conf', 'apache2.conf', '/icons/'],
        'nginx': ['nginx.conf', 'default.conf', '/var/www/html/'],
        
        # New Popular Systems
        'blogger': ['feeds/posts/default', '.blogspot.com', '/b/sitemap.xml'],
        'tikiwiki': ['tiki-index.php', 'tiki-admin.php', '/tiki-css/'],
        'moodle': ['moodle/login/index.php', '/moodle/', '/mod/', '/theme/'],
        'liferay': ['group/guest/', 'c/portal/', '/documents/'],
        'kentico': ['CMSPages/', 'CMSModules/', 'getdoc/'],
        'ghost': ['/ghost/', '/content/images/', 'ghost-sdk.min.js'],
        'prestashop': ['/admin-dev/', '/classes/', '/themes/', 'index.php?controller='],
        'typo3': ['typo3/', 'typo3conf/', 'fileadmin/'],
    }
    
    path_lower = path.lower()
    cms_scores = {}
    
    # Score each CMS based on keyword matches
    for cms_name, keywords in cms_mappings.items():
        score = 0.0
        for keyword in keywords:
            if keyword in path_lower:
                # Longer, more specific keywords score higher
                # Base score: keyword length * 0.05, max 0.3 per keyword
                keyword_score = min(len(keyword) * 0.05, 0.3)
                score += keyword_score
        
        if score > 0:
            cms_scores[cms_name] = score
    
    # Boost filename CMS hint if it matches
    if filename_cms_hint and filename_cms_hint in cms_scores:
        cms_scores[filename_cms_hint] *= 1.5
        logger.debug(f"🔍 Boosted {filename_cms_hint} detection for path {path} (filename hint)")
    
    if not cms_scores:
        # No CMS detected - return hint with low confidence or None
        if filename_cms_hint:
            return (filename_cms_hint, 0.2)  # Low confidence hint
        return (None, 0.0)
    
    # Find CMS with highest score
    best_cms, best_score = max(cms_scores.items(), key=lambda x: x[1])
    
    # Normalize confidence score (0.0-1.0)
    # Higher scores indicate more specific matches
    # Scale: 0.1-0.3 = low confidence, 0.3-0.6 = medium, 0.6+ = high
    confidence = min(best_score / 0.6, 1.0)  # Normalize to 0.0-1.0
    
    # If multiple CMSs have similar scores, reduce confidence (ambiguous)
    sorted_scores = sorted(cms_scores.values(), reverse=True)
    if len(sorted_scores) > 1 and sorted_scores[0] - sorted_scores[1] < 0.1:
        # Close scores = ambiguous, reduce confidence
        confidence *= 0.7
    
    # Handle generic paths that match multiple CMSs
    generic_keywords = ['admin', 'api', 'config', 'themes', 'modules']
    if best_score < 0.2 and any(kw in path_lower for kw in generic_keywords):
        # Generic match - return as 'general' with low confidence
        result = ('general', min(confidence, 0.3))
        # #region agent log
        import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B","location":"upload_wordlist.py:180","message":"Generic path detected","data":{"result":result,"best_score":best_score},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
        # #endregion
        return result
    
    result = (best_cms, confidence)
    # #region agent log
    import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B","location":"upload_wordlist.py:186","message":"detect_cms_for_single_path exit","data":{"result":result,"best_cms":best_cms,"confidence":confidence,"cms_scores_count":len(cms_scores)},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
    # #endregion
    return result


def detect_cms_from_paths(paths: List[str], filename_cms: str = None) -> tuple:
    """
    Detect CMS from path content by counting occurrences.
    Returns: (detected_cms, occurrence_count)
    
    Example: For file 'urls-Drupal-7.20' with 44 occurrences of 'drupal' in paths,
    this will return ('drupal', 44)
    """
    if not paths:
        return (filename_cms, 0) if filename_cms else (None, 0)
    
    # Expanded CMS mappings with high-confidence keywords
    cms_mappings = {
        # Existing Systems
        'wordpress': ['wordpress', 'wp-admin', 'wp-content', 'wp-includes', 'wp-login.php', 'wp-config.php', 'plugins/', 'themes/', '.well-known/wps'],
        'drupal': ['drupal', 'sites/default', 'user/login', 'core/', 'modules/', 'themes/', '/node/'],
        'joomla': ['joomla', 'administrator', 'components', 'templates/', 'media/', 'index.php?option='],
        'magento': ['magento', 'admin', 'catalog', 'pub/static', 'static/version', 'frontend/', 'backend/'],
        'shopify': ['shopify', 'admin', 'themes', 'cdn.shopify.com', 'shop_assets', '/collections/', '/products/'],
        'sitecore': ['sitecore', 'sitecore/admin', '/shell/'],
        'vbulletin': ['vbulletin', 'vb-', 'admincp'],
        'aem': ['aem', 'adobe', 'crx/de', '/editor.html', '/content/dam/'],
        'aspnet': ['asp.net', '.aspx', '.asmx', 'web.config', '__viewstate'],
        'laravel': ['laravel', '/vendor/laravel', '.env', 'mix-manifest.json', '/storage/'],
        'apache': ['.htaccess', 'httpd.conf', 'apache2.conf', '/icons/'],
        'nginx': ['nginx.conf', 'default.conf', '/var/www/html/'],
        
        # New Popular Systems
        'blogger': ['feeds/posts/default', '.blogspot.com', '/b/sitemap.xml'],
        'tikiwiki': ['tiki-index.php', 'tiki-admin.php', '/tiki-css/'],
        'moodle': ['moodle/login/index.php', '/moodle/', '/mod/', '/theme/'],
        'liferay': ['group/guest/', 'c/portal/', '/documents/'],
        'kentico': ['CMSPages/', 'CMSModules/', 'getdoc/'],
        'ghost': ['/ghost/', '/content/images/', 'ghost-sdk.min.js'],
        'prestashop': ['/admin-dev/', '/classes/', '/themes/', 'index.php?controller='],
        'typo3': ['typo3/', 'typo3conf/', 'fileadmin/'],
    }
    
    # Count CMS occurrences in paths
    cms_counts = {}
    paths_lower = ' '.join(paths).lower()
    
    for cms_name, keywords in cms_mappings.items():
        count = sum(paths_lower.count(keyword) for keyword in keywords)
        if count > 0:
            cms_counts[cms_name] = count
    
    # If filename CMS detected, boost its count
    if filename_cms and filename_cms in cms_counts:
        cms_counts[filename_cms] += 10  # Boost filename detection
    
    if not cms_counts:
        return (filename_cms, 0) if filename_cms else (None, 0)
    
    # Return CMS with highest count
    detected_cms = max(cms_counts.items(), key=lambda x: x[1])
    return (detected_cms[0], detected_cms[1])


def calculate_automatic_weight(paths: List[str], filename_cms: str = None, detected_cms: str = None, cms_count: int = 0) -> float:
    """
    Calculate automatic weight based on CMS detection and path patterns,
    using relative density for CMS confidence.
    
    Returns weight between 0.3 and 0.9 (leaving room for learned overrides to reach 1.0)
    """
    if not paths:
        return 0.4  # Default
    
    total_paths = len(paths)
    base_weight = 0.4
    weight = base_weight
    
    # --- 1. CMS Detection Boost (Relative Density) ---
    if detected_cms and cms_count and cms_count > 0:
        # Calculate CMS density: proportion of paths containing a CMS keyword
        cms_density = cms_count / total_paths if total_paths > 0 else 0
        
        # Scale density linearly to a max boost of 0.4 (to keep total < 0.9)
        # 1.0 density (all paths have a keyword) should yield a high boost
        cms_boost = min(0.4, cms_density * 0.5)
        weight += cms_boost
        
        logger.debug(f"🔍 CMS '{detected_cms}' detected: {cms_count} occurrences in {total_paths} paths (density: {cms_density:.2%}, boost: +{cms_boost:.2f})")
    
    # --- 2. High-Value Patterns Boost (Relative to total paths) ---
    high_value_patterns = ['admin', 'config', '.env', 'backup', 'database', 'api', 'login', 'license', '.git', '.svn']
    paths_lower = ' '.join(paths).lower()
    high_value_count = sum(1 for pattern in high_value_patterns if pattern in paths_lower)
    
    # Calculate High-Value density
    high_value_density = high_value_count / total_paths if total_paths > 0 else 0
    
    # Apply boost if density is high
    if high_value_density >= 0.05:  # If 5% of paths are high-value
        weight = min(weight + 0.1, 0.85)
    elif high_value_density >= 0.02:  # If 2% of paths are high-value
        weight = min(weight + 0.05, 0.8)
    
    # --- 3. Final Bounding and Return ---
    # Max confidence for automatically calculated weight should be 0.9, leaving
    # room for human/learned overrides to reach 1.0
    final_weight = max(0.3, min(weight, 0.9))
    
    logger.info(f"⚖️  Calculated automatic weight: {final_weight:.2f} (CMS: {detected_cms or 'none'}, high-value density: {high_value_density:.2%})")
    
    return final_weight


def calculate_weight_for_single_path(
    path: str,
    detected_cms: Optional[str],
    confidence: float,
    filename_cms_hint: Optional[str] = None
) -> float:
    """
    Calculate weight for a single path based on CMS detection and path patterns.
    
    Args:
        path: The path string
        detected_cms: CMS detected for this path (or None)
        confidence: Confidence score from CMS detection (0.0-1.0)
        filename_cms_hint: Optional CMS name from filename to use as hint
    
    Returns:
        Weight value between 0.3 and 0.9
    
    Formula:
        base_weight = 0.4
        cms_boost = confidence * 0.4  # Max +0.4
        high_value_boost = 0.1 if path contains high-value patterns else 0
        filename_hint_boost = 0.05 if detected_cms matches filename_hint else 0
        
        weight = base_weight + cms_boost + high_value_boost + filename_hint_boost
        weight = max(0.3, min(weight, 0.9))  # Bound between 0.3-0.9
    """
    # #region agent log
    import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B","location":"upload_wordlist.py:330","message":"calculate_weight_for_single_path entry","data":{"path":path,"detected_cms":detected_cms,"confidence":confidence,"confidence_type":type(confidence).__name__,"filename_cms_hint":filename_cms_hint},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
    # #endregion
    base_weight = 0.4
    weight = base_weight
    
    # --- 1. CMS Confidence Boost ---
    if detected_cms and confidence > 0:
        # Scale confidence to boost (max +0.4)
        cms_boost = confidence * 0.4
        weight += cms_boost
    
    # --- 2. High-Value Pattern Boost ---
    high_value_patterns = ['admin', 'config', '.env', 'backup', 'database', 'api', 'login', 'license', '.git', '.svn', 'wp-config', 'settings', 'credentials']
    path_lower = path.lower()
    
    # Check if path contains high-value patterns
    high_value_found = any(pattern in path_lower for pattern in high_value_patterns)
    if high_value_found:
        weight = min(weight + 0.1, 0.85)
    
    # --- 3. Filename Hint Boost ---
    if filename_cms_hint and detected_cms and detected_cms == filename_cms_hint:
        # Small boost if detected CMS matches filename hint
        weight = min(weight + 0.05, 0.9)
    
    # --- 4. Final Bounding ---
    final_weight = max(0.3, min(weight, 0.9))
    
    # #region agent log
    import json; log_file = open('/tmp/suzu_debug.log', 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"B","location":"upload_wordlist.py:365","message":"calculate_weight_for_single_path exit","data":{"final_weight":final_weight,"weight":weight,"base_weight":base_weight},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
    # #endregion
    return final_weight


def upload_wordlist_file(
    file_path: Path,
    cms_name: str = None,
    wordlist_name: str = None,
    default_weight: float = 0.4,  # Ignored - weight is automatically calculated
    source: str = "seclist"
):
    """
    Upload a single wordlist file to vector database.
    
    Weight is automatically calculated based on CMS detection and path patterns.
    The default_weight parameter is ignored.
    """
    
    # Load paths
    paths = load_paths_from_file(file_path)
    if not paths:
        logger.warning(f"⚠️  No paths found in {file_path}")
        return
    
    # Infer CMS from filename to use as hint for per-path detection
    filename_cms_hint = None
    if not cms_name:
        filename_cms_hint = infer_cms_from_filename(file_path.name)
        if filename_cms_hint:
            logger.info(f"🔍 Detected filename CMS hint: {filename_cms_hint}")
    else:
        filename_cms_hint = cms_name
    
    # Use filename as wordlist_name if not provided
    if not wordlist_name:
        wordlist_name = file_path.name
    
    # Initialize vector store
    try:
        vector_store = VectorPathStore()
    except Exception as e:
        logger.error(f"❌ Failed to initialize vector store: {e}")
        return
    
    # Upload paths with per-path CMS detection and weight calculation
    logger.info(f"📤 Uploading {len(paths)} paths from {wordlist_name} (per-path detection enabled)...")
    result = vector_store.upload_paths(
        paths=paths,
        wordlist_name=wordlist_name,
        cms_name=cms_name,  # Used as fallback only if per-path detection fails
        default_weight=0.4,  # Used as fallback only if per-path detection fails
        source=source,
        category=None,  # Will be auto-inferred
        per_path_detection=True,  # Enable per-path CMS detection
        filename_cms_hint=filename_cms_hint  # Pass filename hint for per-path detection
    )
    
    logger.info(f"✅ Upload complete: {result['uploaded']} uploaded, {result['failed']} failed")
    
    return result


def upload_directory(directory_path: Path, recursive: bool = False):
    """Upload all wordlist files from a directory"""
    
    # Find all wordlist files
    wordlist_extensions = ['.txt', '.fuzz', '.lst', '.wordlist']
    files_to_upload = []
    
    if recursive:
        for ext in wordlist_extensions:
            files_to_upload.extend(directory_path.rglob(f'*{ext}'))
    else:
        for ext in wordlist_extensions:
            files_to_upload.extend(directory_path.glob(f'*{ext}'))
    
    if not files_to_upload:
        logger.warning(f"⚠️  No wordlist files found in {directory_path}")
        return
    
    logger.info(f"📁 Found {len(files_to_upload)} wordlist files")
    
    total_uploaded = 0
    total_failed = 0
    
    for file_path in files_to_upload:
        logger.info(f"\n{'='*60}")
        logger.info(f"Processing: {file_path}")
        
        result = upload_wordlist_file(
            file_path=file_path,
            cms_name=None,  # Auto-infer
            wordlist_name=None,  # Use filename
            default_weight=0.4,
            source="seclist"
        )
        
        if result:
            total_uploaded += result['uploaded']
            total_failed += result['failed']
    
    logger.info(f"\n{'='*60}")
    logger.info(f"📊 Total: {total_uploaded} uploaded, {total_failed} failed")


def main():
    parser = argparse.ArgumentParser(
        description='Upload wordlist paths to Suzu vector database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Upload single file
  python upload_wordlist.py wordpress.txt --cms-name wordpress --wordlist-name wordpress.fuzz.txt
  
  # Upload directory (non-recursive)
  python upload_wordlist.py /path/to/wordlists/
  
  # Upload directory recursively
  python upload_wordlist.py /path/to/wordlists/ --recursive
  
  # Upload with custom weight
  python upload_wordlist.py wordpress.txt --cms-name wordpress --weight 0.6
        """
    )
    
    parser.add_argument(
        'path',
        type=str,
        help='Path to wordlist file or directory'
    )
    
    parser.add_argument(
        '--cms-name',
        type=str,
        default=None,
        help='CMS name (e.g., wordpress, drupal). Auto-inferred from filename if not provided.'
    )
    
    parser.add_argument(
        '--wordlist-name',
        type=str,
        default=None,
        help='Wordlist name (default: filename)'
    )
    
    parser.add_argument(
        '--weight',
        type=float,
        default=0.4,
        help='Default weight for paths (0.0-1.0, default: 0.4)'
    )
    
    parser.add_argument(
        '--source',
        type=str,
        default='seclist',
        choices=['seclist', 'custom', 'uploaded'],
        help='Source of wordlist (default: seclist)'
    )
    
    parser.add_argument(
        '--recursive',
        action='store_true',
        help='Recursively process directories'
    )
    
    args = parser.parse_args()
    
    path = Path(args.path)
    
    if not path.exists():
        logger.error(f"❌ Path does not exist: {path}")
        sys.exit(1)
    
    if path.is_file():
        # Upload single file
        upload_wordlist_file(
            file_path=path,
            cms_name=args.cms_name,
            wordlist_name=args.wordlist_name,
            default_weight=args.weight,
            source=args.source
        )
    elif path.is_dir():
        # Upload directory
        upload_directory(path, recursive=args.recursive)
    else:
        logger.error(f"❌ Invalid path: {path}")
        sys.exit(1)


if __name__ == '__main__':
    main()

