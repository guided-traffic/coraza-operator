# Instructions

## Operational Target (read first)

[OPERATIONAL_TARGET.md](OPERATIONAL_TARGET.md) defines how this operator is meant to
be operated in the end. A ticket does not have to advance a target — infrastructure,
tooling and delivery work legitimately advances none. It must not run against one:
if a ticket conflicts with a target (`T1`…`T10`) or an invariant (`I1`…`I6`), stop
and propose how to reshape the ticket — or how to amend the target — before
implementing.

## Controller-Runtime Best Practices

- **Reconciliation idempotence:** Every reconcile must be idempotent. Running the same reconcile twice with no external changes must produce identical results.
- **Requeue patterns:** Return errors for retriable failures (controller-runtime will requeue automatically with exponential backoff). Use `ctrl.Result{RequeueAfter: duration}` ONLY for explicit timed requeues. **Never use `Requeue: true` (deprecated).**
- **Finalizers:** When adding finalizers, ensure cleanup logic is bullet-proof. Missing finalizer removal blocks resource deletion indefinitely.
- **Watch predicates:** Use predicates to filter events (generation changes, specific field updates). Avoid unnecessary reconciliations.

## Common Pitfalls

- **Status conditions:** Updates must set all three condition types (Ready, Progressing, Degraded). Missing one leaves stale status.
- **Owner references:** Any resource the operator creates must have an owner reference back to the parent CRD for garbage collection.
- **Context cancellation:** Always respect context cancellation. Don't ignore `ctx.Done()` in long-running operations or HTTP servers.
- **Cache server consistency:** RuleSet cache updates must be atomic. Partial updates can cause WASM plugins to load incomplete/corrupt rules.
- **RBAC drift:** Changes to what the operator reads/writes require updates to RBAC manifests in `config/rbac/`. Run `make manifests` to regenerate.

## Style and Conventions

- Go code must pass `make lint` (golangci-lint, config in `.golangci.yml`).
- Error wrapping: use `fmt.Errorf("context: %w", err)`, not `%v`.
- Logger: use structured logging via `logr`. No `fmt.Println` or `log.Printf`.
- Test assertions: use `testify` (`require` for fatal, `assert` for non-fatal).
- Variable naming: Follow Go conventions. Use `ctx` for context.Context, `req` for reconcile.Request, short names for small scopes, descriptive names for larger scopes.
- Avoid naked returns in functions longer than 5-10 lines.

### Functional Programming Style

Favor a functional programming inspired approach where practical:

- **Pure functions over methods with side effects:** Extract logic into functions that take inputs and return outputs. Keep side effects (API calls, status patches, event recording) at the call site, not buried inside helpers.
- **Small, composable functions:** Break reconciliation logic into focused functions that each do one thing (e.g., `validateAggregatedRules`, `rejectUnsupportedRules`, `buildCacheReadyMessage`, `buildWasmPlugin`).
- **Early returns for error/edge cases:** Handle failures at the top, keep the happy path unindented.
- **Immutable-by-default thinking:** Avoid package-level mutable state when feasible.
