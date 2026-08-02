#!/bin/bash
#
# Runs the pgalchemy integration tests against a throwaway PostgreSQL container.
#
# The unit tests need none of this -- just run `pytest`. Only the tests marked
# `integration` need a database, and they skip themselves when none is reachable.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    docker compose down -v 2>/dev/null || docker-compose down -v 2>/dev/null || true
    echo -e "${GREEN}Cleanup complete${NC}"
}
trap cleanup EXIT

compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    else
        docker-compose "$@"
    fi
}

if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

echo -e "${YELLOW}Starting PostgreSQL...${NC}"
compose down -v >/dev/null 2>&1 || true
compose up -d

echo -e "${YELLOW}Waiting for PostgreSQL to be ready...${NC}"
for attempt in $(seq 1 30); do
    if compose exec -T postgres pg_isready -U testuser -d testdb >/dev/null 2>&1; then
        echo -e "${GREEN}PostgreSQL is ready${NC}"
        break
    fi
    if [ "$attempt" -eq 30 ]; then
        echo -e "${RED}PostgreSQL failed to start in time${NC}"
        exit 1
    fi
    printf '.'
    sleep 1
done

echo -e "\n${YELLOW}Running the full test suite...${NC}"
python -m pytest -v

echo -e "\n${GREEN}All tests passed${NC}"
