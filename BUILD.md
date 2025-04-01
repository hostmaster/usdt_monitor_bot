# Build and Deployment Guide

This document provides instructions for building, testing, and deploying the Crypto Wallet Tracker application.

## Prerequisites

- Docker Engine 24.0 or later
- Docker Buildx
- Make
- Git
- Access to GitHub Container Registry (ghcr.io)

## Environment Setup

1. Clone the repository:
```bash
git clone https://github.com/hostmaster/crypto-wallet-tracker.git
cd crypto-wallet-tracker
```

2. Create required secret files:
```bash
# Create secret files with your values
echo "your-etherscan-api-key" > etherscan_api_key.txt
echo "your-telegram-bot-token" > tg_bot_token.txt
echo "your-telegram-chat-id" > tg_chat_id.txt
echo "your-wallet-address" > wallet_address.txt
```

3. Set up Docker Buildx:
```bash
docker buildx create --use
```

## Build Commands

### Production Build
```bash
# Build production image
make build

# Build and push to registry
make push
```

### Development Build
```bash
# Build development image
make build-dev

# Start development environment
make dev
```

### Testing
```bash
# Run tests
make test
```

## Development Workflow

1. Start the development environment:
```bash
make dev
```

2. The development environment includes:
   - Hot reloading
   - Debugger on port 5678
   - Source code mounted for live updates
   - Development tools and dependencies

3. Connect to the debugger:
   - Use VS Code's Python debugger
   - Or connect to `localhost:5678` with your preferred debugger

## Deployment

### Local Deployment
```bash
# Build and run locally
make build
docker compose up -d
```

### Remote Deployment
```bash
# Deploy to remote server
make deploy TARGET_HOST=your-server TARGET_DIR=/path/to/deploy
```

Required environment variables for deployment:
- `TARGET_HOST`: SSH hostname or IP
- `TARGET_DIR`: Remote deployment directory
- `CR_PAT`: GitHub Container Registry Personal Access Token
- `DOCKER_USER`: Docker registry username

### Environment Variables

The following environment variables can be customized:

```bash
# Build configuration
PYTHON_VERSION=3.11
REGISTRY=ghcr.io
REPOSITORY=hostmaster/crypto-wallet-tracker
GIT_COMMIT=$(git rev-parse --short HEAD)

# Deployment configuration
TARGET_HOST=your-server
TARGET_DIR=~/tracker
```

## Docker Bake Configuration

The project uses Docker Bake for build configuration. Key targets:

- `base`: Common build settings
- `development`: Development environment
- `test`: Testing environment
- `runtime`: Production runtime

### Build Targets

```bash
# Build specific target
docker buildx bake runtime  # Production build
docker buildx bake dev     # Development build
docker buildx bake test    # Test build

# Build all targets
docker buildx bake --all
```

## Maintenance

### Cleanup
```bash
# Remove containers and volumes
make clean

# Remove build cache
docker buildx prune -f
```

### Health Checks

The application includes health checks:
- Interval: 30 seconds
- Timeout: 10 seconds
- Retries: 3

Monitor container health:
```bash
docker compose ps
```

## Troubleshooting

### Common Issues

1. **Build Failures**
   - Check Docker Buildx installation
   - Verify network connectivity
   - Check registry credentials

2. **Runtime Issues**
   - Verify secret files exist
   - Check container logs
   - Verify environment variables

3. **Deployment Issues**
   - Check SSH connectivity
   - Verify remote directory permissions
   - Check registry access

### Logs

View application logs:
```bash
docker compose logs -f tracker
```

## Security Considerations

1. **Secrets Management**
   - Keep secret files secure
   - Use appropriate file permissions
   - Never commit secrets to version control

2. **Container Security**
   - Application runs as non-root user
   - Minimal runtime image
   - Regular security updates

3. **Network Security**
   - Internal network isolation
   - Limited port exposure
   - Secure registry access

## CI/CD Integration

The project is configured for GitHub Actions:

1. **Build Pipeline**
   - Builds on push to main
   - Runs tests
   - Pushes to registry

2. **Deployment Pipeline**
   - Deploys on successful build
   - Uses GitHub secrets
   - Automated versioning

## Support

For issues and support:
1. Check the [GitHub Issues](https://github.com/hostmaster/crypto-wallet-tracker/issues)
2. Review the [Documentation](https://github.com/hostmaster/crypto-wallet-tracker/wiki)
3. Contact the maintainers