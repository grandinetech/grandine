# Quick Notes

## On pico-guest build process

If using the two-stage build, to extract the /target folder:
Run the final stage as a container:

```sh
mkdir elf
container_id=$(docker create pico-build bash)
docker cp "$container_id:/target/riscv32im-risc0-zkvm-elf/release/zkvm_guest_pico" ./target/zkvm_guest_pico.elf
docker rm "$container_id"
```

This copies the build artifacts from the image to ./target on your host.
