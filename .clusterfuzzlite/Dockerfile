FROM gcr.io/oss-fuzz-base/base-builder:v1
RUN apt-get update && apt-get install --no-install-recommends -y ninja-build curl unzip libtool
WORKDIR /usr/local
RUN curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v25.6/protoc-25.6-linux-x86_64.zip && \
    unzip protoc-25.6-linux-x86_64.zip && \
    rm protoc-25.6-linux-x86_64.zip 
COPY . $SRC/hpp-proto
WORKDIR $SRC/hpp-proto
COPY .clusterfuzzlite/build.sh $SRC/
