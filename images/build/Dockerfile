# The image that builds and judges podssh: the gate (scripts/gate.sh, run by
# scripts/dev.sh), CI and the release. This line is the one place that names
# it; the scripts and the workflows read it. The digest is that of the
# multi-platform index (linux/amd64 and linux/arm64), so two runs of one
# commit use one compiler, on each architecture.
FROM docker.io/library/rust:1-alpine@sha256:7e9e2d068a107a2adafd19930011178d14a78326053cd4c3a9f7ad3fd049557d
