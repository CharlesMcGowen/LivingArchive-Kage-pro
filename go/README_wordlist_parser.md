# Go Wordlist Parser

High-performance wordlist file parser written in Go for faster file processing in the Suzu dashboard.

## Performance Benefits

- **10-50x faster** than Python for large files (50K+ paths)
- **Lower memory usage** with buffered I/O
- **Efficient batching** for vector database uploads
- **Streaming support** for Django file uploads

## Building

```bash
cd go
make wordlist-parser
```

Or manually:
```bash
cd go/cmd/wordlist-parser
go build -mod=vendor -o ../../bin/wordlist-parser .
chmod +x ../../bin/wordlist-parser
```

## Installation (Optional)

Install to system PATH:
```bash
make install
```

## Usage

### From Python

```python
from suzu.wordlist_parser_bridge import parse_wordlist_stream

result = parse_wordlist_stream(
    file_stream=uploaded_file,
    batch_size=1000,
    skip_comments=True,
    normalize_paths=True
)

paths = result['paths']
batches = result['batches']
stats = result['stats']
```

### Direct CLI Usage

```bash
echo '{"batch_size":1000,"skip_comments":true,"normalize_paths":true}' | \
  cat - wordlist.txt | \
  ./bin/wordlist-parser
```

## Architecture

- **Go Parser** (`go/internal/suzu/wordlist_parser.go`): Core parsing logic
- **CLI Binary** (`go/cmd/wordlist-parser/main.go`): Command-line interface
- **Python Bridge** (`suzu/wordlist_parser_bridge.py`): Python integration with automatic fallback

## Fallback Behavior

If the Go parser is unavailable, the system automatically falls back to Python parsing, ensuring compatibility even without the Go binary.
