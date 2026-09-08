-- E2E runner for the assay-workflow dashboard.
--
-- Boots a fresh assay engine + the demo worker that emits the canonical
-- pipeline_state.steps[] shape, seeds a workflow, then runs the
-- Playwright suite against it. Exit code = the suite's exit code.
-- Used by both the `dashboard-e2e:test` moon task and the `e2e` mise
-- task, so local + CI behaviour stays identical.
--
-- This script is itself an example of the v0.12 process.* / shell.exec /
-- http surface that any consumer can use to orchestrate test fixtures
-- without dropping to bash.

-- http, env, process, shell, sleep are registered as globals by the
-- assay runtime — no `require` needed.

-- ── Resolve paths relative to the repo root ─────────────────────────
-- The script is invoked as `assay run crates/assay-workflow/tests-e2e/run.lua`
-- from the repo root (mise + moon both set cwd to the workspace root).
local ROOT = env.get("ASSAY_REPO_ROOT") or "."
-- v0.13.0: runtime + engine are two binaries. Engine runs the HTTP API;
-- `assay` runs the worker Lua script.
local ASSAY_BIN = ROOT .. "/target/release/assay"
local ENGINE_BIN = ROOT .. "/target/release/assay-engine"
local HERE = ROOT .. "/crates/assay-workflow/tests-e2e"
local WORKER = HERE .. "/fixtures/demo-worker.lua"

local PORT = tonumber(env.get("ASSAY_E2E_PORT") or "8080")
local BASE = "http://localhost:" .. PORT
local E2E_ROOT
local TMP_ROOT
local DATA_DIR
local ENGINE_CONFIG
local ENGINE_LOG = env.get("ASSAY_E2E_ENGINE_LOG") or "/tmp/assay-e2e-engine.log"
local WORKER_LOG = env.get("ASSAY_E2E_WORKER_LOG") or "/tmp/assay-e2e-worker.log"
-- when state.auth is Some (now always), every /api/v1/engine/workflow/*
-- call except /health|/version|/openapi.json|/docs requires a Bearer
-- admin key. Match the break-glass key seeded in write_engine_config().
local ADMIN_KEY = env.get("ASSAY_E2E_ADMIN_KEY") or "dev-admin-key-change-me"
local ADMIN_HEADERS = { ["Authorization"] = "Bearer " .. ADMIN_KEY }

-- ── Helpers ─────────────────────────────────────────────────────────
local function log(msg)
  io.write("[e2e] " .. msg .. "\n")
  io.flush()
end

local function fail(msg)
  -- error() unwinds through pcall in the main body so teardown still
  -- runs. The unhandled error at the end of the script forces `assay
  -- run` to exit non-zero — that's the signal CI / mise / moon need
  -- to mark the suite failed.
  error("[e2e] FATAL: " .. msg, 0)
end

local function shell_quote(value)
  return "'" .. value:gsub("'", "'\\''") .. "'"
end

local function create_private_data_dir()
  local tmp = shell.exec("cd /tmp && pwd -P")
  if tmp.status ~= 0 then
    fail("unable to resolve the temporary directory: " .. (tmp.stderr or ""))
  end
  TMP_ROOT = (tmp.stdout or ""):gsub("%s+$", "")

  local result = shell.exec("mktemp -d /tmp/assay-workflow-e2e.XXXXXX")
  if result.status ~= 0 then
    fail("unable to create private fixture directory: " .. (result.stderr or ""))
  end

  local created = (result.stdout or ""):gsub("%s+$", "")
  local canonical = shell.exec("cd " .. shell_quote(created) .. " && pwd -P")
  if canonical.status ~= 0 then
    fail("unable to resolve the fixture directory: " .. (canonical.stderr or ""))
  end
  E2E_ROOT = (canonical.stdout or ""):gsub("%s+$", "")
  local expected_prefix = TMP_ROOT .. "/assay-workflow-e2e."
  if E2E_ROOT:sub(1, #expected_prefix) ~= expected_prefix
      or not E2E_ROOT:sub(#expected_prefix + 1):match("^[%w]+$") then
    fail("mktemp returned an unexpected fixture path")
  end

  DATA_DIR = E2E_ROOT .. "/data"
  ENGINE_CONFIG = E2E_ROOT .. "/engine.toml"
  local setup = shell.exec(
    "chmod 0700 " .. shell_quote(E2E_ROOT)
      .. " && mkdir -m 0700 " .. shell_quote(DATA_DIR)
  )
  if setup.status ~= 0 then
    fail("unable to secure fixture directory: " .. (setup.stderr or ""))
  end
end

local function tail(path, max_lines)
  local ok, body = pcall(fs.read, path)
  if not ok or not body then
    return "<unable to read " .. path .. ">"
  end
  local lines = {}
  for line in (body .. "\n"):gmatch("([^\n]*)\n") do
    table.insert(lines, line)
  end
  local selected = {}
  local first = math.max(1, #lines - max_lines + 1)
  for i = first, #lines do
    table.insert(selected, lines[i])
  end
  return table.concat(selected, "\n")
end

-- Write the engine config file pointing at our private SQLite data dir +
-- the port under test. Matches the schema in
-- crates/assay-engine/src/config.rs (v0.13.0 format).
local function write_engine_config()
  local toml = string.format([[
[server]
bind_addr = "127.0.0.1:%d"

[backend]
type = "sqlite"
data_dir = "%s"

# Plan-15 slice 3 (v0.14.0): the engine refuses to start when there are
# no operator users AND no admin api keys. The dashboard e2e never
# bootstraps an admin user, so seed a break-glass key here. The key is
# only consumed by the engine's own gate — the dashboard suite doesn't
# call admin routes, so the value is arbitrary.
[auth]
admin_api_keys = ["dev-admin-key-change-me"]

[logging]
level = "info"
format = "pretty"
]], PORT, DATA_DIR)
  fs.write(ENGINE_CONFIG, toml)
end

-- Poll /api/v1/engine/workflow/version until the engine answers (or give up after 15s).
local function wait_for_engine()
  for _ = 1, 30 do
    local ok, resp = pcall(http.get, BASE .. "/api/v1/engine/workflow/version", { timeout = 1 })
    if ok and resp and resp.status == 200 then return true end
    sleep(0.5)
  end
  return false
end

-- ── Boot ─────────────────────────────────────────────────────────────
local engine_pid, worker_pid

-- Always tear down regardless of how we exit. Lua doesn't have try /
-- finally; wrap the body in pcall and clean up + rethrow on failure.
local function teardown()
  if worker_pid then pcall(process.kill, worker_pid) end
  if engine_pid then pcall(process.kill, engine_pid) end
  -- Reap so we don't leave zombies.
  if worker_pid then pcall(process.wait, worker_pid, { timeout = 3 }) end
  if engine_pid then pcall(process.wait, engine_pid, { timeout = 3 }) end
  local expected_prefix = TMP_ROOT and (TMP_ROOT .. "/assay-workflow-e2e.") or ""
  if E2E_ROOT and E2E_ROOT:sub(1, #expected_prefix) == expected_prefix
      and E2E_ROOT:sub(#expected_prefix + 1):match("^[%w]+$") then
    pcall(shell.exec, "rm -rf -- " .. shell_quote(E2E_ROOT))
  end
end

local ok, err = pcall(function()
  create_private_data_dir()
  write_engine_config()

  log("starting assay-engine on :" .. PORT)
  local h = process.spawn({
    cmd = ENGINE_BIN,
    args = { "serve", "--config", ENGINE_CONFIG },
    stdout = ENGINE_LOG,
    stderr = ENGINE_LOG,
  })
  engine_pid = h.pid

  if not wait_for_engine() then
    fail("engine never came up; tail of " .. ENGINE_LOG .. ":\n" .. tail(ENGINE_LOG, 80))
  end
  log("engine ready (pid " .. engine_pid .. ")")

  log("creating namespace 'demo'")
  local r = http.post(BASE .. "/api/v1/engine/workflow/namespaces", { name = "demo" }, { headers = ADMIN_HEADERS })
  if r.status >= 400 and r.status ~= 409 then
    fail("namespace create failed: " .. r.status .. " " .. (r.body or ""))
  end

  log("starting demo worker (assay runtime)")
  local hw = process.spawn({
    cmd = ASSAY_BIN,
    args = { "run", WORKER },
    stdout = WORKER_LOG,
    stderr = WORKER_LOG,
    -- Worker pulls tasks from the gated /api/v1/engine/workflow/tasks/*
    -- routes; the assay.engine.workflow Lua client reads ASSAY_ADMIN_KEY
    -- when present and forwards it as a Bearer header on every request.
    -- ASSAY_ENGINE_URL lets demo-worker.lua honour the dynamic e2e port
    -- instead of the legacy hard-coded :8080.
    env = {
      ASSAY_ENGINE_URL = BASE,
      ASSAY_ADMIN_KEY = ADMIN_KEY,
    },
  })
  worker_pid = hw.pid
  sleep(1.5) -- let the worker register before we POST the workflow

  log("seeding DemoPipeline (id=demo-2)")
  local rs = http.post(BASE .. "/api/v1/engine/workflow/workflows", {
    workflow_type = "DemoPipeline",
    workflow_id = "demo-2",
    namespace = "demo",
    task_queue = "demo-q",
    input = {},
  }, { headers = ADMIN_HEADERS })
  if rs.status >= 400 then
    fail("workflow seed failed: " .. rs.status .. " " .. (rs.body or ""))
  end

  log("running playwright")
  local res = shell.exec("npx playwright test", {
    cwd = HERE,
    env = {
      ASSAY_E2E_BASE = BASE,
      ASSAY_E2E_ADMIN_KEY = ADMIN_KEY,
      CI = env.get("CI") or "",
    },
  })
  io.write(res.stdout)
  io.stderr:write(res.stderr)
  if res.status ~= 0 then
    fail("playwright suite failed (exit " .. tostring(res.status) .. ")")
  end
end)

teardown()

if not ok then
  -- Re-raise so `assay run` exits non-zero. Without this, a Playwright
  -- failure would leave the script "succeeding" from CI's perspective.
  error(tostring(err), 0)
end
log("OK")
