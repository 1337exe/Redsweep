# Security and responsible use

- Report vulnerabilities in Lowtide through GitHub's **private vulnerability reporting** on this repository (Security tab > Report a vulnerability).
- Lowtide scans nothing, exploits nothing and evades nothing. It records, checks and refuses. Use it only on systems you are authorised to test.
- `--capture`, `--rollback-cmd` and `lowtide wrap` run commands through your shell, as you, on the machine where Lowtide runs. Only put commands you trust in an engagement folder.
  The MCP server never runs commands.
- `lowtide lab` starts a throwaway web app on 127.0.0.1 only and changes only its own folder. Never expose it to a network.
- Secrets that look like keys, tokens or passwords are stored as a fingerprint, never as text. Credential material is never stored, only a hash. Detection covers common shapes; use `--secret` for the rest.
- The journal is **tamper-evident, not tamper-proof**. Sign the closeout and keep its head hashes somewhere an attacker cannot also edit.
- Engagement folders hold hostnames, usernames and paths. Keep them on encrypted storage and out of public repositories.
- A closeout pack contains the journals. Check it before sharing outside the engagement.
