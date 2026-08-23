DROP FUNCTION IF EXISTS ensure_invocation_partition(timestamptz);
DROP INDEX IF EXISTS tool_invocations_principal_idx;
DROP INDEX IF EXISTS tool_invocations_chain_idx;
DROP TABLE IF EXISTS tool_invocations;
