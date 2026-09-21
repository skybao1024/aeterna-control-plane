# Docker Deployment

Only the repository-root Compose topology is supported. Run all commands from
the repository root.

```bash
./deploy.sh init
./deploy.sh dev
./verify-setup.sh dev
```

Production preparation:

```bash
./verify-setup.sh prod
./deploy.sh prod
```

Before production, replace all example credentials, use managed secrets, set an
exact public frontend origin, terminate TLS at a trusted ingress, restrict
diagnostic ports, configure backups, and test restoration. Production recovery
secrets require an approved KMS/HSM integration; database-only encryption is not
sufficient.

`./deploy.sh stop` preserves PostgreSQL and Redis volumes. Volume deletion is a
separate destructive operation and is never part of routine deployment.
