# Changelog

## 0.4.0

### Added

- `terminal id --harness <name>`: a stable per-harness terminal id
  (`<name>:<uuid>` at `~/.sohopay/<name>/terminal_id`). `--harness` takes a
  fixed list: `antigravity`, `claude-code`, `codex`, `cursor`, `hermes`.
- `--terminal <id>` on `key generate`, `pop sign` and `voucher sign`, in place
  of `--out` / `--key`. The key file is
  `~/.agents/sohopay-agent-workload/<sha256-hex(id)>/secret.json`, so two
  installs on one machine get two keys without a `TERMINAL_MISMATCH`.
- `capabilities` advertises the `workload-terminal/1` contract.
- New error code `INVALID_HARNESS`.

Existing `--key` / `--out` paths are unchanged.

## 0.3.1

### Security

- `header_value` is no longer echoed to stdout under `--write-header` (INV-1).
  With `voucher sign --envelope --write-header <path>` the credential is written
  only to the 0600 file; stdout reports `header_file` plus non-secret metadata
  (`payment_id`, `agent_key_jkt`, `header_name`, ...). The `envelope` and
  `signature` fields, which encode the same credential, are omitted too.
  Behavior without `--write-header` is unchanged. 0.3.0 is affected; upgrade.
