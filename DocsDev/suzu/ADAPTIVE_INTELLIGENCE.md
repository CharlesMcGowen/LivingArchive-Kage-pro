# Adaptive Intelligence for Suzu Directory Enumeration

## Overview
Implemented adaptive intelligence features that allow learned path weights to override base priority paths, enabling the system to improve over time based on historical success rates.

## Key Features

### 1. Contextual Path Expansion
- **CMS-Specific Paths**: Automatically loads CMS-specific path patterns when a CMS is detected
- **Weighted Paths**: Each path has an associated weight (0.0-1.0) indicating priority
- **Dynamic Loading**: Paths are loaded based on detected CMS (WordPress, Drupal, Joomla, Magento, Shopify)

### 2. Adaptive Overriding/Weighting
- **Learned Weights**: Loads historical success rates from `DirectoryEnumerationResult` database
- **Override Mechanism**: Learned weights can override base weights if they're higher
- **Context-Aware**: Weights are filtered by CMS type when available
- **Continuous Learning**: System learns from every enumeration and improves over time

## Implementation Details

### Path Learning Module (`suzu/path_learning.py`)

#### `load_learned_path_weights(target_cms: Optional[str]) -> Dict[str, float]`
- Queries `DirectoryEnumerationResult` table for historical data
- Calculates learned weights based on:
  - Average priority score (50% weight)
  - Success rate - status 200 ratio (30% weight)
  - CMS match rate (20% weight)
- Filters by CMS type if provided
- Returns dictionary mapping paths to learned weights (0.0-1.0)

#### `get_cms_specific_paths(cms_name: Optional[str]) -> Dict[str, float]`
- Returns CMS-specific path patterns with weights
- Supports: WordPress, Drupal, Joomla, Magento, Shopify
- Each CMS has curated high-value paths with appropriate weights

### Enhanced Priority Scorer (`suzu/priority_scorer.py`)

#### Initialization
```python
scorer = DirectoryPriorityScorer(target_cms='wordpress')
```
- Loads base priority paths with weights
- Loads CMS-specific paths if CMS is provided
- Loads learned weights from historical data
- CMS-specific paths take precedence over base paths

#### Priority Calculation
The `calculate_priority()` method now:
1. **Checks CMS-specific paths first** (if CMS detected)
   - Uses CMS weight or learned weight (whichever is higher)
2. **Checks base priority paths**
   - Uses base weight or learned weight (whichever is higher)
3. **Checks learned weights for exact path matches**
   - Applies learned weight if meaningful (>0.2)

#### Priority Wordlist Generation
The `get_priority_wordlist()` method now:
- Includes CMS-specific paths (highest priority)
- Includes framework-specific paths
- Includes base priority paths
- Includes learned paths (if not already included)
- **Sorts by weight** (highest first) for optimal enumeration order

## Learning Algorithm

### Weight Calculation Formula
```
learned_weight = (avg_priority * 0.5) + (success_rate * 0.3) + (cms_match_rate * 0.2)
```

Where:
- `avg_priority`: Average priority score from historical enumerations (0.0-1.0)
- `success_rate`: Ratio of status 200 responses (0.0-1.0)
- `cms_match_rate`: Ratio of CMS detections (0.0-1.0)

### Learning Criteria
- Path must appear at least **2 times** in historical data
- Path must have priority score > 0.3
- Learned weight must be > 0.2 to be applied

## Usage Example

```python
from suzu.directory_enumerator import SuzuDirectoryEnumerator

enumerator = SuzuDirectoryEnumerator()

# Enumerate an EggRecord
# The system will:
# 1. Detect CMS from RequestMetaData
# 2. Initialize priority scorer with detected CMS
# 3. Load learned weights for that CMS
# 4. Generate priority wordlist (sorted by weight)
# 5. Enumerate with priority paths first
# 6. Store results with learned weights applied

result = enumerator.enumerate_egg_record(
    egg_record_id="123e4567-e89b-12d3-a456-426614174000",
    write_to_db=True
)

# On subsequent enumerations, learned weights will:
# - Override base weights if higher
# - Boost paths that historically performed well
# - Suppress paths that rarely succeed
```

## Integration Flow

1. **CMS Detection** → Detects CMS from RequestMetaData
2. **Priority Scorer Initialization** → Loads CMS-specific paths and learned weights
3. **Priority Wordlist Generation** → Creates sorted list (highest weight first)
4. **Enumeration** → Checks priority paths first
5. **Priority Calculation** → Applies learned weights during scoring
6. **Storage** → Results stored in DirectoryEnumerationResult
7. **Learning** → Historical data used for future weight calculations

## Benefits

1. **Adaptive**: System improves over time based on success rates
2. **Context-Aware**: Different weights for different CMS types
3. **Efficient**: Prioritizes paths most likely to succeed
4. **Transparent**: Factor breakdown shows why paths are prioritized
5. **Extensible**: Easy to add new CMS types or learning criteria

## Future Enhancements

1. **Machine Learning**: Use ML models for weight prediction
2. **Temporal Learning**: Weight recent successes higher than old ones
3. **Target-Specific Learning**: Learn patterns per domain/IP
4. **Cross-CMS Learning**: Learn which paths work across multiple CMS types
5. **Failure Learning**: Learn from failures to avoid low-value paths

## Files Modified

1. ✅ `suzu/path_learning.py` - New learning module
2. ✅ `suzu/priority_scorer.py` - Enhanced with adaptive intelligence
3. ✅ `suzu/directory_enumerator.py` - Integrated adaptive learning

## Database Requirements

The learning system requires the `DirectoryEnumerationResult` table to be populated with enumeration results. The more data, the better the learning becomes.

**Minimum for Learning**:
- At least 2 occurrences of a path
- Priority score > 0.3
- Historical data across multiple targets

