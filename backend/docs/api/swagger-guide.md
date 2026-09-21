# OpenAPI and Swagger

The service exposes separate documentation applications in development and
preview environments:

- `/client/docs` and `/client/openapi.json`
- `/backoffice/docs` and `/backoffice/openapi.json`
- `/api-docs/client.json` and `/api-docs/backoffice.json`

Client and backoffice routes are registered in
`app/route/router_registry.py`. Update the corresponding OpenAPI tags whenever a
route group changes.

Documentation is not an authorization boundary. Every protected route must
enforce its authentication and authorization dependency even when production
documentation is disabled.

The OpenAPI contract must not advertise generic file upload or cloud-storage
operations. Aeterna control-plane APIs never accept vault content, messages,
media, or attachments.
