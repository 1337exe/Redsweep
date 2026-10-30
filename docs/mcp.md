# Using Redsweep from an AI agent (MCP)

If an AI agent works on part of an engagement, it should follow the same rules as an operator. The Redsweep MCP server gives it those rules as tools.

**What the agent can do:** read the status, check scope, look up the price of an action, log actions (including failures), record a change with its original value,
record a rollback, read back and compare, and list what blocks closeout.

**What it cannot do:** waive a change, record a Control Team decision, resume a freeze, or run any shell command. Capture and rollback commands are disabled in this mode:
the agent passes the values it observed. Those powers stay with people.

## Set up

Start an engagement first (`redsweep init`, edit `scope.json`). Then:

```bash
# Claude Code
claude mcp add redsweep -- redsweep mcp --home /path/to/.redsweep --operator agent-1
```

Claude Desktop or any client that takes a JSON config:

```json
{ "mcpServers": { "redsweep": { "command": "redsweep", "args": ["mcp", "--home", "/path/to/.redsweep", "--operator", "agent-1"] } } }
```

Give the agent its own operator name. Its actions then appear in the report under that name, and its journal file is separate from yours.

## Tell the agent how to behave

Put this in the agent's instructions:

```
Before you touch any host, call redsweep_scope_check. Do not act on "out" or "unlisted".
Before each action, call redsweep_price for its class. Log each action with redsweep_log_action, including failures, and name the assumption you tested.
Before you change anything on a target, call redsweep_change_add with the original value. After you undo it, call redsweep_change_rollback, read the state back,
and call redsweep_change_verify with what you read. Before you say you are finished, call redsweep_closeout_check and fix every blocker.
If redsweep_status says frozen, stop and wait for a person.
```

## What a refusal looks like

The agent gets an error with the reason (for example "refused by the rules of engagement: evil.example: not listed in scope"), so it can correct itself instead of failing silently.
The test kit checks this: `redsweep selftest` step 11.
