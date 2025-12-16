# EggRecord Filter Utility - Usage Guide

This guide shows how to use the reusable Django ORM filter utilities for EggRecords, similar to how they're used in `kage_dashboard` and `eggrecord_list` views.

## Quick Start

The simplest way to use the filter utilities:

```python
from .eggrecord_filters import build_eggrecord_filter_context

def my_view(request):
    context = build_eggrecord_filter_context(request, database_name='customer_eggs')
    return render(request, 'my_template.html', context)
```

That's it! The context will include:
- `eggrecords`: List of filtered eggrecord dictionaries
- `total_eggrecords`: Total count
- `alive_eggrecords`: Count of alive records
- `unique_eggs`: List of eggs for filter dropdown
- `filters`: Current filter values
- `filter_egg_id`: Current egg filter

## Available Functions

### `build_eggrecord_filter_context(request, database_name='customer_eggs')`

**Simplest approach** - Returns a complete context dict ready for templates.

```python
def my_view(request):
    context = build_eggrecord_filter_context(request)
    context.update({
        'title': 'My Page',
        'icon': '🥚',
    })
    return render(request, 'template.html', context)
```

### `get_eggrecords_as_dicts(...)`

Get filtered EggRecords as a list of dictionaries.

**Parameters:**
- `database_name`: Database to use (default: 'customer_eggs')
- `filter_egg_id`: Filter by egg UUID
- `filter_alive`: Filter by alive status (True/False/None)
- `filter_domain`: Filter by domain name (case-insensitive contains)
- `filter_subdomain`: Filter by subdomain (case-insensitive contains)
- `order_by`: Order field (default: '-updated_at')
- `limit`: Limit results (None = no limit)
- `include_annotations`: Include counts (default: True)

**Example:**
```python
from .eggrecord_filters import get_eggrecords_as_dicts

eggrecords = get_eggrecords_as_dicts(
    filter_egg_id='123e4567-e89b-12d3-a456-426614174000',
    filter_alive=True,
    limit=100,
    include_annotations=True
)
```

### `get_eggrecord_queryset(...)`

Get a Django QuerySet (for advanced use cases).

**Returns:** `(queryset, use_annotations)` tuple

**Example:**
```python
from .eggrecord_filters import get_eggrecord_queryset

queryset, use_annotations = get_eggrecord_queryset(
    filter_egg_id='123e4567-e89b-12d3-a456-426614174000',
    filter_alive=True,
    limit=100
)

# You can chain additional Django ORM methods
filtered = queryset.filter(domainname__startswith='example')
```

### `get_eggrecord_counts(...)`

Get count statistics for filtered EggRecords.

**Returns:** Dict with `total`, `alive`, `dead` counts

**Example:**
```python
from .eggrecord_filters import get_eggrecord_counts

counts = get_eggrecord_counts(
    filter_egg_id='123e4567-e89b-12d3-a456-426614174000',
    filter_alive=True
)

print(f"Total: {counts['total']}")
print(f"Alive: {counts['alive']}")
print(f"Dead: {counts['dead']}")
```

### `get_unique_eggs_for_filter(...)`

Get unique eggs that have associated EggRecords (for dropdowns).

**Example:**
```python
from .eggrecord_filters import get_unique_eggs_for_filter

unique_eggs = get_unique_eggs_for_filter(database_name='customer_eggs')
# Returns: [{'id': '...', 'eggName': '...', 'eisystem_in_thorm': '...'}, ...]
```

### `extract_eggrecord_filters_from_request(request)`

Extract filter parameters from Django request.GET.

**Returns:** Dict with `filter_egg_id`, `filter_alive`, `filter_domain`, `filter_subdomain`

**Example:**
```python
from .eggrecord_filters import extract_eggrecord_filters_from_request

filters = extract_eggrecord_filters_from_request(request)
# Extracts: ?egg=123&alive=true&domain=example.com&subdomain=api
```

## Request Parameters

The filter utilities automatically extract these query parameters:

- `egg`: UUID of egg to filter by
- `alive`: 'true'/'false'/'1'/'0'/'yes'/'no' (or empty for all)
- `domain`: Domain name (case-insensitive contains)
- `subdomain`: Subdomain (case-insensitive contains)

**Example URLs:**
```
/reconnaissance/kage/?egg=123e4567-e89b-12d3-a456-426614174000
/reconnaissance/kage/?egg=123e4567-e89b-12d3-a456-426614174000&alive=true
/reconnaissance/kage/?domain=example.com&alive=true
/reconnaissance/kage/?subdomain=api&domain=example.com
```

## Template Usage

The filter utilities work with the existing templates. Here's what you get in your template context:

```django
<!-- Filter Panel -->
<div class="filter-panel">
    <h3>🔍 Filter EggRecords</h3>
    <form method="GET" action="">
        <select name="egg">
            <option value="">All Eggs</option>
            {% for egg in unique_eggs %}
                <option value="{{ egg.id }}" {% if filter_egg_id == egg.id|stringformat:"s" %}selected{% endif %}>
                    {{ egg.eggName }} ({{ egg.eisystem_in_thorm }})
                </option>
            {% endfor %}
        </select>
        <button type="submit">Filter</button>
    </form>
    
    <div class="filter-count">
        Showing {{ total_count }} of {{ total_eggrecords }} eggrecords
        {% if alive_eggrecords %}
            • {{ alive_eggrecords }} alive
        {% endif %}
    </div>
</div>

<!-- EggRecords List -->
{% for eggrecord in eggrecords %}
    <div class="eggrecord-card">
        <h4>{{ eggrecord.subDomain|default:eggrecord.domainname }}</h4>
        <p>Domain: {{ eggrecord.domainname }}</p>
        <p>Status: {{ eggrecord.alive|yesno:"Alive,Dead" }}</p>
        <p>Nmap Scans: {{ eggrecord.nmap_count }}</p>
        <p>HTTP Requests: {{ eggrecord.request_count }}</p>
        <p>DNS Queries: {{ eggrecord.dns_count }}</p>
        {% if eggrecord.egg_name %}
            <p>Egg: {{ eggrecord.egg_name }} ({{ eggrecord.eisystem_name }})</p>
        {% endif %}
    </div>
{% endfor %}
```

## Real-World Examples

### Example 1: Simple Filter View

```python
from django.shortcuts import render
from .eggrecord_filters import build_eggrecord_filter_context

def my_eggrecord_view(request):
    context = build_eggrecord_filter_context(request)
    context.update({
        'title': 'My EggRecords',
        'personality': 'eggrecords'
    })
    return render(request, 'reconnaissance/eggrecord_list.html', context)
```

### Example 2: Advanced Filter with Custom Logic

```python
from django.shortcuts import render
from django.core.paginator import Paginator
from .eggrecord_filters import (
    get_eggrecords_as_dicts,
    get_eggrecord_counts,
    get_unique_eggs_for_filter,
    extract_eggrecord_filters_from_request
)

def advanced_eggrecord_view(request):
    filters = extract_eggrecord_filters_from_request(request)
    
    # Get filtered data
    eggrecords = get_eggrecords_as_dicts(
        filter_egg_id=filters['filter_egg_id'],
        filter_alive=filters['filter_alive'],
        limit=200
    )
    
    # Get counts
    counts = get_eggrecord_counts(
        filter_egg_id=filters['filter_egg_id'],
        filter_alive=filters['filter_alive']
    )
    
    # Get unique eggs
    unique_eggs = get_unique_eggs_for_filter()
    
    # Pagination
    paginator = Paginator(eggrecords, 25)
    page = request.GET.get('page', 1)
    eggrecords_page = paginator.page(page)
    
    context = {
        'eggrecords': eggrecords_page,
        'total_eggrecords': counts['total'],
        'alive_eggrecords': counts['alive'],
        'unique_eggs': unique_eggs,
        'filters': filters,
        'filter_egg_id': filters['filter_egg_id'],
    }
    
    return render(request, 'my_template.html', context)
```

### Example 3: API Endpoint

```python
from django.http import JsonResponse
from .eggrecord_filters import get_eggrecords_as_dicts, extract_eggrecord_filters_from_request

def eggrecord_api(request):
    filters = extract_eggrecord_filters_from_request(request)
    
    eggrecords = get_eggrecords_as_dicts(
        filter_egg_id=filters['filter_egg_id'],
        filter_alive=filters['filter_alive'],
        limit=100
    )
    
    return JsonResponse({
        'success': True,
        'eggrecords': eggrecords,
        'count': len(eggrecords)
    })
```

## Comparison: Before vs After

### Before (Manual Django ORM):

```python
def kage_dashboard(request):
    filter_egg_id = request.GET.get('egg', '').strip()
    
    if 'customer_eggs' in connections.databases:
        try:
            eggrecords_qs = PostgresEggRecord.objects.using('customer_eggs').select_related('egg_id')
            
            if filter_egg_id:
                eggrecords_qs = eggrecords_qs.filter(egg_id_id=filter_egg_id)
            
            eggrecords_qs = eggrecords_qs.annotate(
                nmap_count=Count('nmap_scans', distinct=True),
                request_count=Count('http_requests', distinct=True),
                dns_count=Count('dns_queries', distinct=True)
            ).order_by('-updated_at')
            
            # ... convert to dicts, get counts, etc.
```

### After (Using Filter Utility):

```python
def kage_dashboard(request):
    context = build_eggrecord_filter_context(request)
    # That's it! Context is ready with all filtered data.
```

## Benefits

1. **Reusability**: Use the same filter logic across multiple views
2. **Consistency**: Same filtering behavior everywhere
3. **Maintainability**: Update filter logic in one place
4. **Less Code**: Reduce boilerplate in views
5. **Error Handling**: Built-in error handling and fallbacks
6. **Annotations**: Automatic count annotations (nmap_count, etc.)

## See Also

- `views_eggrecord_filter_example.py` - Complete working examples
- `views.py` - `kage_dashboard()` and `eggrecord_list()` for reference implementations
- `templates/reconnaissance/kage_dashboard.html` - Template filter UI example
- `templates/reconnaissance/eggrecord_list.html` - Template filter UI example

