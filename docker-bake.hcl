variable "PYTHON_VERSION" {
    default = "3.11"
}

variable "REGISTRY" {
    default = "ghcr.io"
}

variable "REPOSITORY" {
    default = "hostmaster/crypto-wallet-tracker"
}

variable "GIT_COMMIT" {
    default = "unknown"
}

# Common settings shared across targets
group "default" {
    targets = ["runtime"]
}

group "ci" {
    targets = ["runtime", "test"]
}

# Base target with shared configuration
target "docker-metadata-action" {
    tags = [
        "${REGISTRY}/${REPOSITORY}:latest",
        "${REGISTRY}/${REPOSITORY}:${GIT_COMMIT}"
    ]
    labels = {
        "org.opencontainers.image.source" = "https://github.com/hostmaster/crypto-wallet-tracker"
        "org.opencontainers.image.revision" = "${GIT_COMMIT}"
    }
}

# Base target with common build settings
target "base" {
    context = "."
    dockerfile = "Dockerfile"
    args = {
        PYTHON_VERSION = "${PYTHON_VERSION}"
        GIT_COMMIT = "${GIT_COMMIT}"
    }
    platforms = ["linux/amd64"]
}

# Development target with additional tools
target "dev" {
    inherits = ["base"]
    target = "development"
    tags = ["${REGISTRY}/${REPOSITORY}:dev"]
}

# Production runtime target
target "runtime" {
    inherits = ["base", "docker-metadata-action"]
    target = "runtime"
}

# Test target for running tests
target "test" {
    inherits = ["base"]
    target = "test"
    output = ["type=cacheonly"]
}