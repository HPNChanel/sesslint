# SessLint release image — offline, zero-runtime-dependency session checker.
# Build context must contain the linux-x86_64 PyInstaller binary as `sesslint`.
#
# PyInstaller binaries are dynamically linked against glibc, so `FROM scratch`
# cannot work. distroless/base-debian12 provides libc + a writable /tmp (needed
# for onefile extraction) with no shell — matching the project's offline,
# minimal-surface posture. `nonroot` runs as uid 65532.
FROM gcr.io/distroless/base-debian12:nonroot
COPY sesslint /sesslint
ENTRYPOINT ["/sesslint"]
