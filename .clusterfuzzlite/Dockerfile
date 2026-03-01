FROM gcr.io/oss-fuzz-base/base-builder:v1
RUN apt-get update && apt-get install --no-install-recommends -y ninja-build curl unzip libtool
WORKDIR /usr/local
ARG PROTOC_VERSION=34.0
RUN set -eux; \
    archive="protoc-${PROTOC_VERSION}-linux-x86_64.zip"; \
    url="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${archive}"; \
    curl -fL --retry 5 --retry-delay 2 --retry-all-errors -o "${archive}" "${url}"; \
    unzip -t "${archive}"; \
    unzip "${archive}"; \
    rm "${archive}"
COPY . $SRC/hpp-proto
WORKDIR $SRC/hpp-proto
COPY .clusterfuzzlite/build.sh $SRC/
