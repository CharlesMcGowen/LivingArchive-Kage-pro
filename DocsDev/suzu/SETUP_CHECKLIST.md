# Suzu Vector Store - Setup Checklist

## ✅ Priority Steps to Complete

### Step 1: Start Qdrant Service
```bash
cd /home/ego/github_public/LivingArchive-Kage-pro
docker compose -f docker/docker-compose.yml up -d qdrant
```

**Verify:**
```bash
docker ps | grep qdrant
curl http://localhost:6333/health
```

### Step 2: Install Python Dependencies
```bash
# Activate your virtual environment first
cd /home/ego/github_public/LivingArchive-Kage-pro
pip install qdrant-client sentence-transformers numpy
```

**Or install all requirements:**
```bash
pip install -r requirements.txt
```

### Step 3: Test Vector Store Connection
```bash
python3 suzu/test_vector_store.py
```

**Expected output:**
- ✅ VectorPathStore import successful
- ✅ Vector store initialized
- ✅ Uploaded test paths
- ✅ Found similar paths
- ✅ Retrieved weighted paths

### Step 4: Upload SecLists CMS Wordlists
```bash
python3 suzu/upload_wordlist.py \
    /media/ego/328010BE80108A8D3/ego/EgoWebs1/SecLists/Discovery/Web-Content/CMS/ \
    --recursive
```

**This will:**
- Auto-detect CMS from filenames (wordpress, drupal, joomla, etc.)
- Upload all .txt, .fuzz, .lst, .wordlist files
- Set default weight of 0.4
- Categorize paths automatically

### Step 5: Verify API Endpoints
```bash
# Test weighted paths endpoint
curl "http://localhost:9000/reconnaissance/api/suzu/paths/weighted/?cms_name=wordpress&limit=10"
```

### Step 6: Restart Suzu Daemon (if needed)
```bash
cd /home/ego/github_public/LivingArchive-Kage-pro
docker compose -f docker/docker-compose.yml restart suzu-daemon
```

## 🔍 Verification Commands

### Check Qdrant Status
```bash
docker logs recon-qdrant --tail 20
curl http://localhost:6333/collections
```

### Check Vector Store Collection
```bash
curl http://localhost:6333/collections/suzu_paths
```

### Test Similarity Search via API
```bash
curl -X POST http://localhost:9000/reconnaissance/api/suzu/paths/similar/ \
  -H "Content-Type: application/json" \
  -d '{
    "query_path": "/wp-admin/",
    "cms_name": "wordpress",
    "limit": 5
  }'
```

## 📊 Expected Results

After setup:
- ✅ Qdrant running on port 6333
- ✅ Vector store collection `suzu_paths` created
- ✅ Wordlists uploaded (check count in collection)
- ✅ Suzu daemon can query vector DB
- ✅ API endpoints responding

## 🐛 Troubleshooting

### Issue: "Qdrant client not available"
**Fix:** `pip install qdrant-client`

### Issue: "Connection refused" to Qdrant
**Fix:** 
```bash
docker compose -f docker/docker-compose.yml up -d qdrant
# Wait 5 seconds, then test
curl http://localhost:6333/health
```

### Issue: "Sentence transformers not available"
**Fix:** `pip install sentence-transformers`

### Issue: Django settings error
**Fix:** Ensure `DJANGO_SETTINGS_MODULE=ryu_project.settings` is set

### Issue: Vector store returns empty results
**Fix:** Upload wordlists first using `upload_wordlist.py`

## 📝 Next Steps After Setup

1. **Monitor Suzu enumeration logs** - Should show vector DB queries
2. **Check enumeration results** - Paths should be weighted
3. **Update weights** - As Suzu learns, weights improve automatically
4. **Add custom wordlists** - Use upload script or API

## 🎯 Success Criteria

- [ ] Qdrant service running
- [ ] Dependencies installed
- [ ] Test script passes
- [ ] Wordlists uploaded
- [ ] API endpoints working
- [ ] Suzu using vector DB paths

