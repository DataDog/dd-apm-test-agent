# simple hack to build the same image on OSX. otherwise the Nix docker build will by default not cross compile to linux
# in CI or on linux systems - use `nix build .#image | docker load -i result` instead

FROM nixos/nix AS builder
RUN   set -xe; \
    echo 'sandbox = true' >> /etc/nix/nix.conf; \
    echo 'filter-syscalls = false' >> /etc/nix/nix.conf; \
    echo 'max-jobs = auto' >> /etc/nix/nix.conf; \
    echo 'experimental-features = nix-command flakes' >> /etc/nix/nix.conf

WORKDIR /build
COPY flake.lock *.nix .

RUN nix flake show


COPY . .

RUN nix build .#image
RUN mkdir -p /output; mkdir -p /img
# very simplistic way to unpack image - relies only on there being a single layer
RUN tar -xf result --strip-components=1 -C /img 
RUN tar -xf /img/layer.tar -C /output

FROM scratch AS final
COPY --from=builder /output/ /

ENTRYPOINT ["/bin/ddapm-test-agent"]