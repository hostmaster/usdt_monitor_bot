# Features Documentation

This directory contains comprehensive documentation for all features of the USDT Monitor Bot.

## Available Features

### 🛡️ [Spam Detection](./spam-detection/)
Advanced transaction filtering to detect and warn about address poisoning attacks, dust attacks, and other malicious transaction patterns.

**Status:** ✅ Production Ready

**Key Capabilities:**
- 7 distinct detection filters
- Real-time risk scoring (0-100)
- Historical transaction analysis
- Configurable thresholds
- Enhanced user notifications

[View Spam Detection Documentation →](./spam-detection/)

---

## Adding New Features

When adding a new feature, please:

1. Create a new directory: `docs/features/<feature-name>/`
2. Add comprehensive documentation including:
   - Feature overview and purpose
   - Implementation details
   - Configuration options
   - Usage examples
   - API reference (if applicable)
3. Update this README with a link to the new feature
4. Follow the documentation structure used in existing features

## Documentation Structure

Each feature directory should contain:

- `README.md` - Main feature documentation and index
- `implementation.md` - Technical implementation details (optional)
- `user-guide.md` - User-facing documentation (optional)
- `api-reference.md` - API documentation (if applicable)
- Any additional relevant documentation files

---

**Last Updated:** 2026-01-04

