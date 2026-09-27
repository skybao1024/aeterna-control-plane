# OpenAPI and Swagger

The service exposes separate documentation applications in development and
preview environments:

- `/client/docs` and `/client/openapi.json`
- `/backoffice/docs` and `/backoffice/openapi.json`
- `/api-docs/client.json` and `/api-docs/backoffice.json`

Client and backoffice routes are registered in
`app/route/router_registry.py`. Update the corresponding OpenAPI tags whenever a
route group changes.

The client account/device routes implement the public desktop protocol v1 at:

- `POST /api/v1/account-challenges`
- `POST /api/v1/account-challenges/{challenge_id}/verify`
- `POST /api/v1/device-bindings`
- `POST /api/v1/device-bindings/{binding_id}/approvals`
- `POST /api/v1/device-bindings/{binding_id}/delayed-confirmations`
- `POST /api/v1/device-bindings/{binding_id}/cancellations`

These routes manually enforce the public transport boundary before Pydantic
validation: exact JSON media type, a 16,384-byte limit, UTF-8 I-JSON, no BOM,
no duplicate members, closed schemas, and matching protocol versions. Their
OpenAPI request bodies are supplied from the same closed Pydantic models even
though runtime parsing is manual.

Successes contain `protocol_version`, `request_id`, and a closed `data` object.
Failures contain the protocol version, an optional syntactically valid request
ID, and a stable nonlocalized `error.code`. Device-binding, delayed-confirmation,
and cancellation grants use an opaque one-use token in the `Authorization:
Bearer` header. Existing-device approval instead requires the registered
device's Ed25519 signature. The legacy password/JWT client-auth router is not
registered; backoffice authentication is unchanged.

Documentation is not an authorization boundary. Every protected route must
enforce its authentication and authorization dependency even when production
documentation is disabled.

The OpenAPI contract must not advertise generic file upload or cloud-storage
operations. Aeterna control-plane APIs never accept vault content, messages,
media, or attachments.
