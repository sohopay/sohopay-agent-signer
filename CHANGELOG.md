# Changelog

## 0.3.1

### Security

- `header_value` is no longer echoed to stdout under `--write-header` (INV-1).
  With `voucher sign --envelope --write-header <path>` the credential is written
  only to the 0600 file; stdout reports `header_file` plus non-secret metadata
  (`payment_id`, `agent_key_jkt`, `header_name`, ...). The `envelope` and
  `signature` fields, which encode the same credential, are omitted too.
  Behavior without `--write-header` is unchanged. 0.3.0 is affected; upgrade.
