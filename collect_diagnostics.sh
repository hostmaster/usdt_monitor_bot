#!/bin/bash
# Diagnostic collection script for file descriptor leak debugging

CONTAINER_NAME=${1:-"telegram-bot"}
COMPOSE_FILE=${2:-"compose.yaml"}

echo "=== File Descriptor Diagnostics ==="
echo "Timestamp: $(date)"
echo ""

echo "1. Debug log (last 200 lines):"
echo "-----------------------------------"
docker compose -f "$COMPOSE_FILE" exec "$CONTAINER_NAME" tail -n 200 /app/data/debug.log 2>/dev/null || echo "No debug.log found"
echo ""

echo "2. Process file descriptor count:"
echo "-----------------------------------"
docker compose -f "$COMPOSE_FILE" exec "$CONTAINER_NAME" sh -c "ls -1 /proc/self/fd 2>/dev/null | wc -l || echo 'Cannot access /proc/self/fd'" 2>/dev/null
echo ""

echo "3. File descriptor limits:"
echo "-----------------------------------"
docker compose -f "$COMPOSE_FILE" exec "$CONTAINER_NAME" python -c "import resource; print('Soft:', resource.getrlimit(resource.RLIMIT_NOFILE)[0]); print('Hard:', resource.getrlimit(resource.RLIMIT_NOFILE)[1])" 2>/dev/null
echo ""

echo "4. Open file descriptors (first 50):"
echo "-----------------------------------"
docker compose -f "$COMPOSE_FILE" exec "$CONTAINER_NAME" sh -c "ls -l /proc/1/fd 2>/dev/null | head -50 || echo 'Cannot access /proc/1/fd'" 2>/dev/null
echo ""

echo "5. Network connections:"
echo "-----------------------------------"
docker compose -f "$COMPOSE_FILE" exec "$CONTAINER_NAME" sh -c "netstat -an 2>/dev/null | grep ESTABLISHED | wc -l || ss -an 2>/dev/null | grep ESTAB | wc -l || echo 'netstat/ss not available'" 2>/dev/null
echo ""

echo "6. Container stats:"
echo "-----------------------------------"
docker compose -f "$COMPOSE_FILE" exec "$CONTAINER_NAME" sh -c "cat /proc/self/status | grep -E '^(Threads|FDSize|VmSize|VmRSS):'" 2>/dev/null
echo ""

echo "7. Application logs (last 50 lines with FD/connection errors):"
echo "-----------------------------------"
docker compose -f "$COMPOSE_FILE" logs --tail=50 "$CONTAINER_NAME" 2>/dev/null | grep -iE "(file descriptor|connection|fd|connector)" || echo "No relevant logs found"
echo ""

echo "8. Python process info:"
echo "-----------------------------------"
docker compose -f "$COMPOSE_FILE" exec "$CONTAINER_NAME" sh -c "ps aux | grep python || echo 'ps not available'" 2>/dev/null
echo ""

echo "=== End Diagnostics ==="
