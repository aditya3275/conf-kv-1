# Locked Contracts — Conf-kv-1

## 1. Authentication

Tenant identity is derived from a verified bearer credential.

A client-supplied `tenant_id` is never trusted for authentication or
authorization.

The exact credential hashing/KDF implementation is deferred to Phase 2.

---

## 2. Request Identity

Every request receives a UUID4 `request_id` at the Gateway.

The request ID is used only for:

- correlation
- logging
- tracing
- VerifKV provenance

`request_id` is not part of OPA policy semantics.

---

## 3. Scheduler

The Scheduler recommends a logical serving backend.

It does not:

- allocate GPUs
- move a live vLLM process
- directly authorize requests

Output:

```json
{
  "backend_id": "vllm-secure-01",
  "zone": "secure",
  "reason": "..."
}