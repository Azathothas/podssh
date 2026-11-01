# Tailscale's own image, for the tailscaled nodes of scripts/ts-headscale.sh
# (T-334): the target, with Tailscale SSH, and the peer of OpenSSH's path.
# Pinned to the digest of its index (tailscale/tailscale:v1.104.4, Dependabot's
# GitHub #78 of 2026-11-01). headscale 0.29.7's table of client versions ends
# at an older release, but this one joins its tailnet: the harness's 14 runs
# passed on it in Actions (T-386).
FROM docker.io/tailscale/tailscale:v1.104.4@sha256:ed6480b33c6eb67c9cbd203ed42b9fb57e361986725b6856def71b7a3d9e276c
