# Coder SSH Gateway

**Unofficial community project; not affiliated with Coder.**

Coder SSH Gateway is a narrow SSH jump server that bridges SSH public-key authentication to Coder workspace access via `coder ssh --stdio`. It authenticates devices/users by SSH key, maps each key to a Coder account, stores encrypted session tokens, and proxies `direct-tcpip` channels to the official Coder CLI.

See [coder-ssh-gateway-design.md](./coder-ssh-gateway-design.md) for the full research and implementation specification.
