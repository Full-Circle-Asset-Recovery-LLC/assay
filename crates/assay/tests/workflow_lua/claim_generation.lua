-- Execute the source builders directly, without a running engine or network.
local ctx_mod = dofile("stdlib/engine/workflow/ctx.lua")

local function yielded(fn)
  local ok, command = coroutine.resume(coroutine.create(fn))
  assert.eq(ok, true)
  return command
end

for _, mode in ipairs({ true, false }) do
  local ctx = ctx_mod.make("example-workflow", {})
  local command = yielded(function()
    ctx:execute_activity("verify", {}, { claim_generation_fencing = mode })
  end)
  assert.eq(command.type, "ScheduleActivity")
  assert.eq(command.claim_generation_fencing, mode)
end

local legacy = ctx_mod.make("example-workflow", {})
local legacy_command = yielded(function() legacy:execute_activity("verify", {}) end)
assert.eq(legacy_command.claim_generation_fencing, nil)

local parallel = ctx_mod.make("example-workflow", {})
local batch = yielded(function()
  parallel:execute_parallel({
    { name = "protected", opts = { claim_generation_fencing = true } },
    { name = "legacy", opts = { claim_generation_fencing = false } },
    { name = "default" },
  })
end)
assert.eq(batch._batch, true)
assert.eq(batch.commands[1].claim_generation_fencing, true)
assert.eq(batch.commands[2].claim_generation_fencing, false)
assert.eq(batch.commands[3].claim_generation_fencing, nil)
print("LUA_CLAIM_GENERATION_BUILDERS_PASS")
