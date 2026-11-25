-- ULRE Control Plane PostgreSQL Schema (Phase 2+)

CREATE TABLE IF NOT EXISTS hosts (
    id               UUID PRIMARY KEY,
    hostname         TEXT NOT NULL,
    machine_id       TEXT UNIQUE NOT NULL,
    os_name          TEXT NOT NULL,
    kernel_version   TEXT NOT NULL,
    cpu_cores        INTEGER NOT NULL,
    memory_bytes     BIGINT NOT NULL,
    cgroup_v2        BOOLEAN NOT NULL,
    controllers      TEXT[] NOT NULL DEFAULT '{}',
    psi_supported    BOOLEAN NOT NULL DEFAULT FALSE,
    swap_accounting  BOOLEAN NOT NULL DEFAULT FALSE,
    oom_group_supported BOOLEAN NOT NULL DEFAULT FALSE,
    btf_supported    BOOLEAN NOT NULL DEFAULT FALSE,
    agent_version    TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('online','degraded','offline')),
    last_seen_at     TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policies (
    id                     UUID PRIMARY KEY,
    name                   TEXT UNIQUE NOT NULL,
    group_name             TEXT NOT NULL,
    version                INTEGER NOT NULL DEFAULT 1,
    priority               INTEGER NOT NULL DEFAULT 100,
    mode                   TEXT NOT NULL CHECK (mode IN ('enforce','dry_run','disabled')),
    criticality            TEXT NOT NULL CHECK (criticality IN ('critical','high','normal','best_effort')),
    allow_destructive      BOOLEAN NOT NULL DEFAULT FALSE,
    allow_runtime_override BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by            TEXT,
    approved_at            TIMESTAMPTZ,
    selectors              JSONB NOT NULL,
    limits                 JSONB NOT NULL,
    oom_policy             JSONB NOT NULL,
    signature              TEXT,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workloads (
    host_id          UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    pid              INTEGER NOT NULL,
    ppid             INTEGER NOT NULL,
    start_time_ticks BIGINT NOT NULL,
    comm             TEXT NOT NULL,
    exe_path         TEXT NOT NULL,
    cmdline          TEXT NOT NULL DEFAULT '',
    uid              INTEGER NOT NULL,
    gid              INTEGER NOT NULL,
    cgroup_path      TEXT NOT NULL,
    systemd_unit     TEXT,
    container_id     TEXT,
    owner_runtime    TEXT NOT NULL,
    matched_policy   TEXT,
    rss_bytes        BIGINT NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (host_id, pid, start_time_ticks)
);

CREATE TABLE IF NOT EXISTS oom_events (
    id              TEXT PRIMARY KEY,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    hostname        TEXT NOT NULL,
    policy_name     TEXT,
    target          TEXT NOT NULL,
    action          TEXT NOT NULL,
    result          TEXT NOT NULL,
    dry_run         BOOLEAN NOT NULL DEFAULT FALSE,
    details         JSONB NOT NULL DEFAULT '{}',
    occurred_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS ebpf_programs (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    version         INTEGER NOT NULL,
    sha256          TEXT NOT NULL,
    program_type    TEXT NOT NULL,
    attach_target   TEXT NOT NULL,
    sections        TEXT[] NOT NULL DEFAULT '{}',
    has_btf         BOOLEAN NOT NULL DEFAULT FALSE,
    min_kernel      TEXT NOT NULL,
    status          TEXT NOT NULL,
    approved_by     TEXT,
    approved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id              TEXT PRIMARY KEY,
    actor           TEXT NOT NULL,
    actor_role      TEXT NOT NULL,
    host_id         TEXT,
    action          TEXT NOT NULL,
    policy_name     TEXT,
    target          TEXT NOT NULL,
    dry_run         BOOLEAN NOT NULL DEFAULT FALSE,
    result          TEXT NOT NULL,
    details         JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
