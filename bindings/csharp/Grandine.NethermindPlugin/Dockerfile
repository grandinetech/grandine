ARG NETHERMIND_VERSION=latest

FROM --platform=$TARGETPLATFORM nethermind/nethermind:$NETHERMIND_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl-dev && apt-get clean

COPY libgrandine.so ./plugins/
COPY Grandine.NethermindPlugin.dll ./plugins/
