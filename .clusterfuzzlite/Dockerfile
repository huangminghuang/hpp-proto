FROM gcr.io/oss-fuzz-base/base-builder@sha256:b9d9eae2a36dc27e2c853aaf754f90d3daaa2d8b2b1b7903699643e797a1af93
RUN apt-get update && apt-get install --no-install-recommends -y ninja-build curl unzip libtool
WORKDIR /usr/local
ARG PROTOC_VERSION=34.0
ARG PROTOC_SHA256=e9a91b6fcfe4177ec2cd35fc8f15c1e811fa0ecdef9372755cd6d3513d5faaab
RUN set -eux; \
    archive="protoc-${PROTOC_VERSION}-linux-x86_64.zip"; \
    url="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${archive}"; \
    curl -fL --retry 5 --retry-delay 2 --retry-connrefused -o "${archive}" "${url}"; \
    echo "${PROTOC_SHA256}  ${archive}" | sha256sum -c -; \
    unzip -t "${archive}"; \
    unzip "${archive}"; \
    rm "${archive}"
COPY . $SRC/hpp-proto
WORKDIR $SRC/hpp-proto
COPY .clusterfuzzlite/build.sh $SRC/
