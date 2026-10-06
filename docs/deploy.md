# Azure Deployment

Live: <https://spraytrace.ambitiousfield-440a14b7.eastasia.azurecontainerapps.io>

One container on Azure Container Apps. FastAPI serves both the API and the
built dashboard, so there is a single deployable unit and no cross-origin
configuration in production.

## Shape

```
Dockerfile
  stage 1  node:20-alpine   npm ci && npm run build   ->  dist/
  stage 2  python:3.13-slim pip install, copy src/ + dist/ -> /app/static
                            generate_data at build time (seed 42)
                            non-root user, uvicorn on $PORT
```

Data is generated **at build time**, so every container starts from identical
reproducible input and the image carries no external dependency.

## Deploy

```bash
RG=spraytrace-rg
ACR=spraytraceacr3072
LOC=eastasia

az group create -n $RG -l $LOC
az acr create -n $ACR -g $RG -l $LOC --sku Basic --admin-enabled true
az containerapp env create -n spraytrace-env -g $RG -l $LOC

# --provenance=false matters; see "Gotchas" below.
docker build --platform linux/amd64 --provenance=false --sbom=false \
  -t $ACR.azurecr.io/spraytrace:v2 .
az acr login -n $ACR
docker push $ACR.azurecr.io/spraytrace:v2

PW=$(az acr credential show -n $ACR --query "passwords[0].value" -o tsv)
az containerapp create -n spraytrace -g $RG --environment spraytrace-env \
  --image $ACR.azurecr.io/spraytrace:v2 \
  --registry-server $ACR.azurecr.io --registry-username $ACR --registry-password "$PW" \
  --target-port 8000 --ingress external \
  --cpu 1.0 --memory 2.0Gi --min-replicas 1 --max-replicas 1
```

Redeploy after a change:

```bash
docker build --platform linux/amd64 --provenance=false --sbom=false \
  -t $ACR.azurecr.io/spraytrace:v3 .
docker push $ACR.azurecr.io/spraytrace:v3
az containerapp update -n spraytrace -g $RG --image $ACR.azurecr.io/spraytrace:v3
```

## Gotchas hit during this deployment

**Region policy.** Azure for Students restricts deployment regions. `centralindia`,
`eastus`, `westus2`, `westeurope` and `eastus2` were all refused. The allowed set
comes from the policy itself:

```bash
az policy assignment list \
  --query "[?contains(displayName,'region')].parameters" -o json
# -> indiasouthcentral, eastasia, indonesiacentral, koreacentral, uaenorth
```

**ACR Tasks are not permitted** on this subscription, so `az acr build` fails
with `TasksOperationsNotAllowed`. Build locally with `--platform linux/amd64`
and push instead.

**Multi-arch manifests fail to pull.** Docker's default buildx output includes
an attestation manifest with a null architecture. Container Apps cannot resolve
it and reports *"image was not found in the registry"* even though
`az acr repository show-tags` lists the tag. `--provenance=false --sbom=false`
produces a single-arch manifest that works. This error message is actively
misleading — the image is present; it is the manifest shape that is wrong.

**Pushes can report success while failing.** A `docker push` exited 0 with a
layer that had timed out mid-upload, leaving the repository empty. Verify with
`az acr repository show-tags` rather than trusting the exit code.

**`min-replicas 1`** keeps one instance warm. Scale-to-zero adds a cold start of
several seconds on first request, which is not what you want in a live demo.

## Cost

Basic ACR plus one always-on 1 vCPU / 2 GiB container app. Within Azure for
Students credit. Tear down with:

```bash
az group delete -n spraytrace-rg --yes --no-wait
```

## The local path is still primary

`./run.sh` runs everything locally with no cloud dependency. Azure is an
addition, not a requirement — if the venue network fails, the demo runs from
the laptop exactly as it does here.
