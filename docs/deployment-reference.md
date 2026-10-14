# Deployment Reference (Optional)

This document describes the optional deployment-reference assets added under `deploy/`.
It does not change the application. The existing `Dockerfile`, `compose.yaml`, and workflow remain unchanged.

## Multi-stage image

Build:

```bash
docker build -f deploy/docker/Dockerfile.multistage -t identityguard:local .
```

Run:

```bash
docker run --rm -p 8000:8000 \
  -e IDENTITYGUARD_JWT_SECRET=local-only-secret \
  -e IDENTITYGUARD_SEED_PASSWORD=Local-Passw0rd-123 \
  -e IDENTITYGUARD_AUTO_SEED=true \
  -e IDENTITYGUARD_DATABASE_URL=sqlite:////data/identityguard.db \
  identityguard:local
```

Health check:

```bash
curl http://localhost:8000/health
```

## Compose reference

```bash
docker compose -f deploy/docker/docker-compose.reference.yml up --build
```

## Kubernetes reference

These manifests are reference-only and should not be applied to a real cluster without reviewing:
- secret management
- persistent volume storage
- image registry and tagging
- TLS and ingress
- database choice, because SQLite is not suitable for high-availability deployment

Apply only in a local learning cluster after validating the images:

```bash
kubectl apply -f deploy/kubernetes/
```

## Jenkins reference

`deploy/jenkins/Jenkinsfile` provides a simple pipeline shape:
1. Checkout
2. Install dependencies
3. Run pytest
4. Build container image
5. Document deployment steps

It is intentionally a reference and does not deploy automatically.

## CI stages to replicate in any platform

Recommended stage set:
1. checkout
2. install dependencies
3. run unit and API tests
4. run fresh-clone smoke test
5. build Docker image
6. run container health check
7. build frontend
8. attach test/report artifacts

The repository's existing GitHub Actions workflow already demonstrates all of these stages.

## Honest positioning

Use wording such as:
- "Authored non-production Kubernetes deployment reference manifests."
- "Built multi-stage Docker references for a FastAPI application."
- "Configured CI stages for automated tests and container builds."
- "Documented local and container deployment steps."