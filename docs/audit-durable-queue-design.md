# Durable Audit Queue — Design Note (G1, non-goal for now)

The current audit writer (`internal/services/async_audit.go`) buffers entries
in an in-memory channel and batch-inserts into MySQL. Two guarantees are
missing for strict compliance deployments:

1. **Durability**: an entry buffered in memory is LOST on process crash or
   buffer overflow (the loss is observable — `finnapigo_audit_entries_dropped_total`
   — but the entry is gone).
2. **No cross-replica backpressure**: each replica flushes independently;
   a DB outage longer than the buffer drains stops audit capture on all of them.

## Recommended future design: Redis Streams

Given the existing `REDIS_URL` seam (S1/S2 use the same shared store),
Redis Streams is the smallest durable step up:

```
replica ──XADD audit:events * <json>──▶ Redis Stream (MAXLEN ~ capped)
                                              │
single consumer group worker ──XREADGROUP──▶ batch INSERT ──▶ MySQL
       (leader-elected, S2)          ▲ XACK only after insert commit
```

Key properties to preserve:

- **At-least-once delivery, idempotent consumer**: XACK after the batch
  insert commits; a crashed worker redelivers, so the insert must be
  idempotent (deterministic entry ID column + `INSERT IGNORE` semantics,
  or dedupe on `(instance, entry_seq)`).
- **Ordering**: per-user ordering only needs the stream's natural FIFO;
  global ordering is NOT a goal (audit consumers sort by `created_at, id`).
- **Backpressure**: `MAXLEN ~ N` caps memory; when the stream is full the
  writer MUST fall back to the current in-memory buffer + dropped-entry
  metric rather than block auth requests (the A6 contract: audit failure
  never breaks a request).
- **PII**: the stream payload inherits the same retention window
  (`AUDIT_RETENTION_DAYS`) — add `XTRIM` by age in the consumer loop.

## Alternatives considered

- **Kafka / managed queues**: strictly better durability/throughput, but a
  new always-on dependency for a low-volume stream (audit entries are
  ~1/request, not 1000s/sec) — not justified yet.
- **Outbox table in MySQL** (transactional write with the domain row):
  strongest guarantee (audit row commits atomically with the business
  change) but doubles write load on the main OLTP DB and needs the same
  relay worker; keep as the option if audits ever become legally
  transactional.

## Decision

Deferred — implementation is explicitly a NON-goal of the enterprise
readiness program (§7). The dropped-entry metric and retention purge in
place today are the accepted baseline; revisit if a deployment requires
lossless audit capture.
