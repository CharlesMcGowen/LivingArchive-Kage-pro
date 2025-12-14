# Suzu Vector Path Store - Setup Guide

## Overview
Suzu now uses a vector database to store and retrieve weighted paths for directory enumeration. This enables:
- **Semantic path matching** - Find similar paths using embeddings
- **Weighted enumeration** - Prioritize paths based on learned weights
- **CMS-specific paths** - Automatically filter paths by detected CMS
- **Bulk wordlist upload** - Import wordlists from SecLists or custom sources

## Quick Start

### 1. Start Qdrant Service
```bash
cd /home/ego/github_public/LivingArchive-Kage-pro
docker compose -f docker/docker-compose.yml up -d qdrant
```

Verify Qdrant is running:
```bash
curl http://localhost:6333/health
```

### 2. Install Python Dependencies
```bash
# In your virtual environment
pip install qdrant-client sentence-transformers numpy
```

Or install all requirements:
```bash
pip install -r requirements.txt
```

### 3. Test Vector Store
```bash
python3 suzu/test_vector_store.py
```

### 4. Upload Wordlists

#### Single File
```bash
python3 suzu/upload_wordlist.py /path/to/wordpress.txt \
    --cms-name wordpress \
    --wordlist-name wordpress.fuzz.txt \
    --weight 0.4
```

#### Directory (Recursive)
```bash
python3 suzu/upload_wordlist.py \
    /media/ego/328010BE80108A8D3/ego/EgoWebs1/SecLists/Discovery/Web-Content/CMS/ \
    --recursive
```

#### Via REST API
```bash
curl -X POST http://localhost:9000/reconnaissance/api/suzu/paths/upload/ \
  -H "Content-Type: application/json" \
  -d '{
    "wordlist_name": "wordpress.fuzz.txt",
    "cms_name": "wordpress",
    "paths": ["/wp-admin/", "/wp-content/", "/wp-config.php"],
    "default_weight": 0.4,
    "source": "seclist"
  }'
```

## API Endpoints

### Upload Paths
**POST** `/reconnaissance/api/suzu/paths/upload/`
```json
{
  "wordlist_name": "wordpress.fuzz.txt",
  "cms_name": "wordpress",
  "paths": ["/wp-admin/", "/wp-content/"],
  "default_weight": 0.4,
  "source": "seclist",
  "category": "admin"
}
```

### Find Similar Paths
**POST** `/reconnaissance/api/suzu/paths/similar/`
```json
{
  "query_path": "/admin",
  "cms_name": "wordpress",
  "limit": 10,
  "threshold": 0.7
}
```

### Get Weighted Paths
**GET** `/reconnaissance/api/suzu/paths/weighted/?cms_name=wordpress&limit=100&min_weight=0.2`

## How It Works

### Hybrid Embeddings
Each path is encoded using:
1. **Structural Features** (8 dims):
   - Path length, depth (slashes), file extension
   - Contains digits, hidden files, admin/api/config patterns
   
2. **Semantic Embeddings** (384 dims):
   - Sentence transformer (all-MiniLM-L6-v2)
   - Contextual description: "This path '/wp-admin/' is an admin directory endpoint for wordpress technology"

### Vector Database
- **Qdrant** (default): Fast, production-ready vector DB
- **ChromaDB** (fallback): Lightweight, embedded option

### Integration with Suzu
1. Suzu detects CMS from target
2. Queries vector DB for weighted paths matching CMS
3. Merges with priority wordlists
4. Uses weighted paths for enumeration
5. Learns from results to update weights

## Configuration

### Environment Variables
- `QDRANT_HOST` - Qdrant host (default: localhost)
- `QDRANT_PORT` - Qdrant port (default: 6333)
- `CHROMA_DB_PATH` - ChromaDB storage path (default: ./chroma_db)

### Docker Compose
Qdrant service is configured in `docker/docker-compose.yml`:
- Port 6333 (HTTP API)
- Port 6334 (gRPC API)
- Persistent volume: `qdrant_storage`

## Troubleshooting

### Qdrant Connection Failed
```bash
# Check if Qdrant is running
docker ps | grep qdrant

# Check logs
docker logs recon-qdrant

# Restart Qdrant
docker compose -f docker/docker-compose.yml restart qdrant
```

### Import Errors
```bash
# Install missing dependencies
pip install qdrant-client sentence-transformers numpy
```

### Django Settings Error
Make sure `DJANGO_SETTINGS_MODULE=ryu_project.settings` is set correctly.

## Next Steps

1. **Upload SecLists CMS wordlists**:
   ```bash
   python3 suzu/upload_wordlist.py /path/to/SecLists/Discovery/Web-Content/CMS/ --recursive
   ```

2. **Monitor Suzu enumeration** - Suzu will automatically use vector DB paths

3. **Update weights** - As Suzu learns from results, weights will be updated

4. **Query similar paths** - Use the API to find related paths for new targets

