# Native ARM64 Docker connectivity smoke

This branch contains generic test code only. CircleCI runs an ARM machine executor, builds a native AArch64 C executable in Docker, verifies its ELF architecture, and runs the container without network access. Artifacts retain host, Docker, image, and executable evidence. No task sources, answers, or credentials are included.

Passing this smoke establishes access to native ARM64 Docker execution. It does not establish that any specific EdgeBench task image or grader works on ARM64.
