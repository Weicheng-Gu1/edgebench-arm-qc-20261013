FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache gcc musl-dev binutils
COPY smoke.c /src/smoke.c
RUN gcc -std=c11 -O2 -Wall -Wextra -Werror /src/smoke.c -o /usr/local/bin/arm64-smoke \
    && readelf -h /usr/local/bin/arm64-smoke | grep -E 'Machine:.*AArch64'
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/arm64-smoke"]
