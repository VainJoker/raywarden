set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

# Use rustup's proxies before version-manager shims, so the project file wins.
export PATH := justfile_directory() / ".tools/bin" + ":" + env("CARGO_HOME", env("HOME") / ".cargo") / "bin" + ":" + env("PATH")
export WRANGLER_SEND_METRICS := "false"
export WRANGLER_LOG_PATH := env("WRANGLER_LOG_PATH", justfile_directory() / ".wrangler/logs")

# Let the project toolchain file select Rust, including its targets/components.
unexport RUSTUP_TOOLCHAIN

wrangler := "node node_modules/wrangler/bin/wrangler.js"

default:
    @just --list

# Explicitly refresh dependency lockfiles; review before committing.
lock:
    npm install --package-lock-only --ignore-scripts --no-audit --no-fund
    cargo generate-lockfile

# Prepare missing or outdated tools; unchanged installations are reused.
setup: setup-node setup-rust setup-worker-build
    cargo fetch --locked

# Deployment runner: install only the locked Wrangler dependencies.
setup-deploy: setup-node

# Stamp only successful installs, including the Node ABI and lockfile identity.
setup-node:
    #!/usr/bin/env bash
    set -euo pipefail
    node_stamp=$(node --input-type=module <<'NODE'
    import { createHash } from "node:crypto";
    import { readFileSync } from "node:fs";
    const hash = createHash("sha256");
    for (const file of ["package.json", "package-lock.json"]) hash.update(readFileSync(file));
    hash.update(`${process.platform}/${process.arch}/${process.versions.modules}/${process.env.npm_config_omit ?? ""}/${process.env.npm_config_ignore_scripts ?? ""}`);
    console.log(hash.digest("hex"));
    NODE
    )
    if [[ -f node_modules/.raywarden-deps && "$(cat node_modules/.raywarden-deps)" == "$node_stamp" ]] && {{ wrangler }} --version >/dev/null 2>&1; then
      echo "Node dependencies are ready"
    else
      npm ci --include=dev --include=optional --ignore-scripts=false --no-audit --no-fund
      {{ wrangler }} --version
      printf '%s\n' "$node_stamp" > node_modules/.raywarden-deps
    fi

setup-rust:
    #!/usr/bin/env bash
    set -euo pipefail
    rust_channel=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
    [[ -n "$rust_channel" ]] || { echo "Missing Rust channel in rust-toolchain.toml" >&2; exit 1; }
    if rustup run "$rust_channel" rustc --version >/dev/null 2>&1 \
      && rust_targets=$(rustup target list --installed --toolchain "$rust_channel") \
      && [[ $'\n'"$rust_targets"$'\n' == *$'\nwasm32-unknown-unknown\n'* ]] \
      && rust_components=$(rustup component list --installed --toolchain "$rust_channel") \
      && [[ "$rust_components" == *rustfmt-* && "$rust_components" == *clippy-* ]]; then
      echo "Rust toolchain and WASM target are ready"
    else
      rustup toolchain install --no-self-update
    fi

setup-worker-build: setup-rust
    #!/usr/bin/env bash
    set -euo pipefail
    worker_version=$(node -p "require('./package.json').config.workerBuildVersion")
    if [[ -x .tools/bin/worker-build && "$(.tools/bin/worker-build --version)" == "$worker_version" ]]; then
      echo "worker-build $worker_version is ready"
    else
      cargo install worker-build --version "=$worker_version" --locked --root .tools
    fi

coverage-setup:
    rustup toolchain install --no-self-update
    rustup component add llvm-tools-preview
    cargo install cargo-llvm-cov --version "=$(node -p "require('./package.json').config.llvmCovVersion")" --locked --root .tools

coverage:
    cargo llvm-cov --lib --locked --lcov --output-path coverage/lcov.info

doctor:
    node --version
    npm --version
    rustc --version
    cargo --version
    rustup target list --installed
    just --version
    .tools/bin/worker-build --version
    {{ wrangler }} --version

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# Check the actual Worker target, not only the host target.
check:
    cargo check --target wasm32-unknown-unknown --locked

lint:
    cargo clippy --target wasm32-unknown-unknown --locked --no-deps

test-rust:
    cargo test --lib --locked

test-js:
    node --test --test-isolation=none tests/*.test.mjs

# Run the existing release WASM in workerd without sockets or application data.
test-worker:
    node tests/run-worker-runtime.mjs

test-sql:
    python3 -m unittest discover -s tests -p '*sql*.py'

test: test-js test-sql test-rust

ci: fmt-check test-js test-sql test-rust check lint

# Shared with Wrangler's custom build command; never installs tools implicitly.
build:
    XDG_CACHE_HOME="${XDG_CACHE_HOME:-$PWD/.tools/cache}" .tools/bin/worker-build --release --locked

# Remove generated files and project caches; preserve local data and installed tools/dependencies.
clean:
    rm -rf -- target build coverage public static/web-vault .tools/cache
    rm -rf -- .wrangler/tmp .wrangler/logs .wrangler/deploy-check .wrangler/artifact-manifest.json .wrangler/verification .wrangler/*-smoke .wrangler/compiled-config-*
    find tests scripts -type d -name __pycache__ -prune -exec rm -rf -- {} +

# Prepare existing assets offline; download the pinned release if unusable.
ui:
    #!/usr/bin/env bash
    set -euo pipefail
    if node --input-type=module <<'NODE'
    import { readFileSync } from "node:fs";
    import { pinnedVersion } from "./scripts/patch-ui.mjs";
    try {
      const version = pinnedVersion(process.cwd());
      const metadata = JSON.parse(readFileSync("static/web-vault/vw-version.json", "utf8"));
      const html = readFileSync("static/web-vault/index.html", "utf8");
      if (metadata.version !== version || !/<\/head\s*>/i.test(html)) process.exit(1);
    } catch { process.exit(1); }
    NODE
    then
      just ui-offline
    else
      just ui-download
    fi

# Explicit offline preparation, without downloading or replacing releases.
ui-offline:
    bash scripts/prepare-ui.sh

ui-download:
    bash scripts/prepare-ui.sh --download

ui-archive archive:
    bash scripts/prepare-ui.sh --archive "$1"

# Regenerate the structural reference snapshot; application databases use db-migrate.
schema:
    #!/usr/bin/env python3
    import sqlite3
    from pathlib import Path

    migrations = sorted(Path("sql/migrations").glob("*.sql"))
    db = sqlite3.connect(":memory:")
    db.execute("PRAGMA foreign_keys=ON")
    for migration in migrations:
        db.executescript(migration.read_text())
    objects = db.execute("""
        SELECT sql FROM sqlite_schema
        WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*'
          AND tbl_name != 'd1_migrations'
        ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1
                 WHEN 'view' THEN 2 ELSE 3 END, name
    """).fetchall()
    db.close()
    header = (
        "-- Generated by `just schema`; edit migrations and regenerate this file.\n"
        f"-- Current structure through {migrations[-1].name}.\n"
        "-- For reading, migration review and disposable SQLite analysis.\n"
        "-- Application initialization and upgrades use `just db-migrate`.\n"
        "-- Contains no business data, seed data or d1_migrations history; not a backup.\n\n"
    )
    Path("sql/schema.sql").write_text(header + ";\n\n".join(sql for (sql,) in objects) + ";\n")
    print(f"Generated sql/schema.sql from {len(migrations)} migrations ({len(objects)} objects)")

# Local by default; only an explicit production argument selects the remote database.
db-migrate environment="local":
    #!/usr/bin/env bash
    set -euo pipefail
    case "$1" in
      local) args=(--config wrangler.local.jsonc --env "" --local --persist-to .wrangler/local) ;;
      production)
        node scripts/deploy.mjs config
        args=(--config wrangler.jsonc --env "" --remote)
        ;;
      *) echo "Expected database target: local or production" >&2; exit 2 ;;
    esac
    {{ wrangler }} d1 migrations apply warden-db "${args[@]}"

# Read-only verification of the configured Cloudflare resources.
resources:
    node scripts/deploy.mjs resources

config:
    node scripts/deploy.mjs config

health:
    node scripts/deploy.mjs health

# Always local: production routes and bindings never enter this command.
dev: setup-node setup-worker-build ui (db-migrate "local")
    {{ wrangler }} dev --local --config wrangler.local.jsonc --env "" --persist-to .wrangler/local

dry-run: ui
    node scripts/deploy.mjs config
    # Wrangler retains stale modules in --outdir; reset only the production bundle.
    rm -rf -- .wrangler/deploy-check/production
    {{ wrangler }} deploy --dry-run --outdir .wrangler/deploy-check/production --config wrangler.jsonc --env ""

# Upload a previously verified integration artifact without rebuilding it.
deploy-worker:
    node scripts/deploy.mjs worker

artifact:
    node scripts/deploy.mjs manifest

artifact-check:
    node scripts/deploy.mjs verify

# Production deployment; each failed step stops the sequence.
deploy:
    just dry-run
    just artifact
    just artifact-check
    just resources
    just db-migrate production
    just deploy-worker
    just health
