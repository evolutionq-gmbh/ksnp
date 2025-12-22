ARG IMAGE=debian:bookworm-slim
ARG DEBIAN_FRONTEND=noninteractive

FROM ${IMAGE} AS build

ARG DEBIAN_FRONTEND

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build gcc g++ libjson-c-dev uuid-dev

WORKDIR /ksnp

COPY . .

RUN cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=ON
RUN cmake --build build --parallel

FROM ${IMAGE}

ARG DEBIAN_FRONTEND

RUN apt-get update && apt-get install -y --no-install-recommends \
    libjson-c5 libuuid1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /ksnp/build/server /ksnp/build/client /usr/bin/

CMD ["echo", "Run 'server' or 'client'"]
