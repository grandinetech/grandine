EXCLUDES = --workspace --exclude zkvm_host --exclude zkvm_guest_risc0 --exclude c_grandine --exclude csharp_grandine
FEATURES = --features default-networks
TARGET ?= 

# build with metrics collection for core crates (transition_functions, helper_functions)
# e.g. make METRICS=1
ifeq ($(METRICS),1)
	FEATURES := $(FEATURES) --features metrics
endif

# build without tracing support for core crates (transition_functions, helper_functions)
# e.g. make DISABLE_TRACING=1
DISABLE_TRACING ?= 0

ifeq ($(DISABLE_TRACING),0)
	FEATURES := $(FEATURES) --features tracing
endif

.PHONY: all
all: build

.PHONY: clean
clean:
	cargo clean
	rm -rf build
	rm -rf bindings/c/build
	rm -rf bindings/csharp/Grandine.NethermindPlugin/bin
	rm -rf bindings/csharp/Grandine.NethermindPlugin/obj

.PHONY: check
check:
	cargo check ${FEATURES} $(EXCLUDES)

.PHONY: build
build:
	cargo build --release --bin grandine $(FEATURES) $(EXCLUDES)

.PHONY: download-spec-tests
download-spec-tests:
	./scripts/download_spec_tests.sh

.PHONY: test
test: download-spec-tests
	cargo test --release --features stub-grandine-version $(EXCLUDES)

.PHONY: release
release:
ifeq ($(TARGET),)
	cargo build --profile compact --bin grandine $(FEATURES) $(EXCLUDES)
else
	@make $(TARGET)
endif

# ------ GRANDINE LINUX X64 ------

.PHONY: x86_64-unknown-linux-gnu
x86_64-unknown-linux-gnu: ./target/x86_64-unknown-linux-gnu/compact/libgrandine.so ./target/x86_64-unknown-linux-gnu/compact/grandine

./target/x86_64-unknown-linux-gnu/compact/grandine:
	cross build --bin grandine --target x86_64-unknown-linux-gnu $(FEATURES) --profile compact $(EXCLUDES)

./target/x86_64-unknown-linux-gnu/compact/libgrandine.so:
	cross build -p c_grandine --profile compact --target x86_64-unknown-linux-gnu

# ------ GRANDINE LINUX ARM64 ------

.PHONY: aarch64-unknown-linux-gnu
aarch64-unknown-linux-gnu: ./target/aarch64-unknown-linux-gnu/compact/grandine ./target/aarch64-unknown-linux-gnu/compact/libgrandine.so

./target/aarch64-unknown-linux-gnu/compact/grandine:
	cross build --bin grandine --target aarch64-unknown-linux-gnu $(FEATURES) --profile compact $(EXCLUDES)

./target/aarch64-unknown-linux-gnu/compact/libgrandine.so:
	cross build -p c_grandine --profile compact --target aarch64-unknown-linux-gnu

# ------ GRANDINE WINDOWS X64 ------

.PHONY: x86_64-pc-windows-msvc
x86_64-pc-windows-msvc: ./target/x86_64-pc-windows-msvc/compact/grandine.exe ./target/x86_64-pc-windows-msvc/compact/grandine.dll

./target/x86_64-pc-windows-msvc/compact/grandine.exe:
	cargo build --profile compact --bin grandine --target x86_64-pc-windows-msvc $(FEATURES) $(EXCLUDES)

./target/x86_64-pc-windows-msvc/compact/grandine.dll:
	cargo build -p c_grandine --profile compact --target x86_64-pc-windows-msvc

# ------ GRANDINE MACOS X64 ------

.PHONY: x86_64-apple-darwin
x86_64-apple-darwin: ./target/x86_64-apple-darwin/compact/grandine ./target/x86_64-apple-darwin/compact/libgrandine.dylib

./target/x86_64-apple-darwin/compact/grandine:
	cargo build --profile compact --bin grandine --target x86_64-apple-darwin $(FEATURES) $(EXCLUDES)

./target/x86_64-apple-darwin/compact/libgrandine.dylib:
	cargo build -p c_grandine --profile compact --target x86_64-apple-darwin

# ------ GRANDINE MACOS ARM64 ------

.PHONY: aarch64-apple-darwin
aarch64-apple-darwin: ./target/aarch64-apple-darwin/compact/grandine ./target/aarch64-apple-darwin/compact/libgrandine.dylib

./target/aarch64-apple-darwin/compact/grandine:
	cargo build --profile compact --bin grandine --target aarch64-apple-darwin $(FEATURES) $(EXCLUDES)

./target/aarch64-apple-darwin/compact/libgrandine.dylib:
	cargo build -p c_grandine --profile compact --target aarch64-apple-darwin

# ------ GRANDINE-NETHERMIND INTEGRATION ------

NETHERMIND_VERSION ?=

.PHONY: nethermind-plugin
nethermind-plugin: ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll
./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll:
	cd ./bindings/csharp && \
	dotnet publish -c Release

.PHONY: download-nethermind
download-nethermind:
	@mkdir -p build
	@curl -s "https://api.github.com/repos/NethermindEth/nethermind/releases/tags/$(NETHERMIND_VERSION)" | \
	jq -r --arg rid "$(RID)" '.assets[] | select(.name | endswith($$rid + ".zip")) | .browser_download_url' | \
	xargs -r -n1 curl -L -o "build/nethermind-$(NETHERMIND_VERSION)-$(TARGET).zip"

.PHONY: pack-grandine-nethermind
pack-grandine-nethermind: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-x64.zip ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-arm64.zip ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-windows-x64.zip ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-x64.zip ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-arm64.zip

# ------ GRANDINE-NETHERMIND LINUX X64 ------

.PHONY: grandine-nethermind-linux-x64
grandine-nethermind-linux-x64: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-x64.zip
./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-x64: ./build/nethermind-$(NETHERMIND_VERSION)-x86_64-unknown-linux-gnu.zip ./target/x86_64-unknown-linux-gnu/compact/libgrandine.so ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll
	unzip ./build/nethermind-$(NETHERMIND_VERSION)-x86_64-unknown-linux-gnu.zip -d ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-x64
	cp ./target/x86_64-unknown-linux-gnu/compact/libgrandine.so ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-x64/plugins
	cp ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-x64/plugins

./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-x64.zip: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-x64
	zip -r ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-x64.zip ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-x64/*

./build/nethermind-$(NETHERMIND_VERSION)-x86_64-unknown-linux-gnu.zip:
	@make download-nethermind NETHERMIND_VERSION=$(NETHERMIND_VERSION) RID=linux-x64 TARGET=x86_64-unknown-linux-gnu

# ------ GRANDINE-NETHERMIND LINUX ARM64 ------

.PHONY: grandine-nethermind-linux-arm64
grandine-nethermind-linux-arm64: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-arm64.zip
./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-arm64: ./build/nethermind-$(NETHERMIND_VERSION)-aarch64-unknown-linux-gnu.zip ./target/aarch64-unknown-linux-gnu/compact/libgrandine.so ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll
	unzip ./build/nethermind-$(NETHERMIND_VERSION)-aarch64-unknown-linux-gnu.zip -d ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-arm64
	cp ./target/aarch64-unknown-linux-gnu/compact/libgrandine.so ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-arm64/plugins
	cp ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-arm64/plugins

./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-arm64.zip: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-arm64
	zip -r ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-arm64.zip ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-linux-arm64/*

./build/nethermind-$(NETHERMIND_VERSION)-aarch64-unknown-linux-gnu.zip:
	@make download-nethermind NETHERMIND_VERSION=$(NETHERMIND_VERSION) RID=linux-arm64 TARGET=aarch64-unknown-linux-gnu.zip

# ------ GRANDINE-NETHERMIND WINDOWS X64 ------

.PHONY: grandine-nethermind-windows-x64
grandine-nethermind-windows-x64: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-windows-x64.zip
./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-windows-x64: ./build/nethermind-$(NETHERMIND_VERSION)-x86_64-pc-windows-msvc.zip ./target/x86_64-pc-windows-msvc/compact/grandine.dll ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll
	unzip ./build/nethermind-$(NETHERMIND_VERSION)-x86_64-pc-windows-msvc.zip -d ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-windows-x64
	cp ./target/x86_64-pc-windows-msvc/compact/grandine.dll ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-windows-x64/plugins
	cp ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-windows-x64/plugins

./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-windows-x64.zip: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-windows-x64
	zip -r ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-windows-x64.zip ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-windows-x64/*

./build/nethermind-$(NETHERMIND_VERSION)-x86_64-pc-windows-msvc.zip:
	@make download-nethermind NETHERMIND_VERSION=$(NETHERMIND_VERSION) RID=windows-x64 TARGET=x86_64-pc-windows-msvc.zip

# ------ GRANDINE-NETHERMIND MACOS X64 ------

.PHONY: grandine-nethermind-macos-x64
grandine-nethermind-macos-x64: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-x64.zip
./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-x64: ./build/nethermind-$(NETHERMIND_VERSION)-x86_64-apple-darwin.zip ./target/x86_64-apple-darwin/compact/libgrandine.dylib ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll
	unzip ./build/nethermind-$(NETHERMIND_VERSION)-x86_64-apple-darwin.zip -d ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-x64
	cp ./target/x86_64-apple-darwin/compact/libgrandine.dylib ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-x64/plugins
	cp ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-x64/plugins

./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-x64.zip: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-x64
	zip -r ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-x64.zip ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-x64/*

./build/nethermind-$(NETHERMIND_VERSION)-x86_64-apple-darwin.zip:
	@make download-nethermind NETHERMIND_VERSION=$(NETHERMIND_VERSION) RID=macos-x64 TARGET=x86_64-apple-darwin

# ------ GRANDINE-NETHERMIND MACOS ARM64 ------

.PHONY: grandine-nethermind-macos-arm64
grandine-nethermind-macos-arm64: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-arm64.zip
./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-arm64: ./build/nethermind-$(NETHERMIND_VERSION)-aarch64-apple-darwin.zip ./target/aarch64-apple-darwin/compact/libgrandine.dylib ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll
	unzip ./build/nethermind-$(NETHERMIND_VERSION)-aarch64-apple-darwin.zip -d ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-arm64
	cp ./target/aarch64-apple-darwin/compact/libgrandine.dylib ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-arm64/plugins
	cp ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-arm64/plugins

./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-arm64.zip: ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-arm64
	zip -r ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-arm64.zip ./build/grandine-$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION)-macos-arm64/*

./build/nethermind-$(NETHERMIND_VERSION)-aarch64-apple-darwin.zip:
	@make download-nethermind NETHERMIND_VERSION=$(NETHERMIND_VERSION) RID=macos-arm64 TARGET=aarch64-apple-darwin

# ----- DOCKER -----

DOCKER_REPO ?= sifrai/grandine
DOCKER_LABEL ?=
DOCKER_SUFFIX ?=

ifneq ($(strip $(DOCKER_SUFFIX)),)
override DOCKER_SUFFIX := -$(DOCKER_SUFFIX)
endif

ifneq ($(strip $(GRANDINE_VERSION)),)
override DOCKER_SUFFIX := -$(GRANDINE_VERSION)
endif

.PHONY: docker
docker: grandine-docker nethermind-docker

# ----- GRANDINE DOCKER -----

.PHONY: grandine-docker
grandine-docker: grandine-docker-arm64 grandine-docker-amd64
ifeq ($(DOCKER_LABEL),)
	@echo "Failed to build docker image - please provide DOCKER_LABEL=, either 'stable' or 'unstable'"
	@exit 1
endif
	docker buildx imagetools create -t $(DOCKER_REPO):$(DOCKER_LABEL)$(DOCKER_SUFFIX) \
		$(DOCKER_REPO):$(DOCKER_LABEL)-amd64$(DOCKER_SUFFIX) \
		$(DOCKER_REPO):$(DOCKER_LABEL)-arm64$(DOCKER_SUFFIX)
ifeq ($(DOCKER_LABEL),stable)
	docker buildx imagetools create -t $(DOCKER_REPO):$(GRANDINE_VERSION) \
		$(DOCKER_REPO):$(DOCKER_LABEL)$(DOCKER_SUFFIX)
	docker buildx imagetools create -t $(DOCKER_REPO):latest \
		$(DOCKER_REPO):$(DOCKER_LABEL)$(DOCKER_SUFFIX)
endif

.PHONY: grandine-docker-arm64
grandine-docker-arm64: ./target/aarch64-unknown-linux-gnu/compact/grandine
ifeq ($(DOCKER_LABEL),)
	@echo "Failed to build docker image - please provide DOCKER_LABEL=, either 'stable' or 'unstable'"
else
	docker buildx build \
		--file Dockerfile.cross \
		--platform linux/arm64 \
		--push \
		--tag $(DOCKER_REPO):$(DOCKER_LABEL)-arm64$(DOCKER_SUFFIX) \
		./target/aarch64-unknown-linux-gnu/compact
endif

.PHONY: grandine-docker-amd64
grandine-docker-amd64: ./target/x86_64-unknown-linux-gnu/compact/grandine
ifeq ($(DOCKER_LABEL),)
	@echo "Failed to build docker image - please provide DOCKER_LABEL=, either 'stable' or 'unstable'"
else
	docker buildx build \
		--file Dockerfile.cross \
		--platform linux/amd64 \
		--push \
		--tag $(DOCKER_REPO):$(DOCKER_LABEL)-amd64$(DOCKER_SUFFIX) \
		./target/x86_64-unknown-linux-gnu/compact
endif

# ----- GRANDINE-NETHERMIND DOCKER -----

.PHONY: nethermind-docker
nethermind-docker: nethermind-docker-arm64 nethermind-docker-amd64
ifeq ($(DOCKER_LABEL),)
	@echo "Failed to build docker image - please provide DOCKER_LABEL=, either 'stable' or 'unstable'"
	@exit 1
endif
	docker buildx imagetools create -t $(DOCKER_REPO):$(DOCKER_LABEL)$(DOCKER_SUFFIX)-nethermind-$(NETHERMIND_VERSION) \
		$(DOCKER_REPO):$(DOCKER_LABEL)-amd64$(DOCKER_SUFFIX)-nethermind-$(NETHERMIND_VERSION) \
		$(DOCKER_REPO):$(DOCKER_LABEL)-arm64$(DOCKER_SUFFIX)-nethermind-$(NETHERMIND_VERSION)
ifeq ($(DOCKER_LABEL),stable)
	docker buildx imagetools create -t $(DOCKER_REPO):$(GRANDINE_VERSION)-nethermind-$(NETHERMIND_VERSION) \
		$(DOCKER_REPO):$(DOCKER_LABEL)$(DOCKER_SUFFIX)-nethermind-$(NETHERMIND_VERSION)
endif

.PHONY: nethermind-docker-arm64
nethermind-docker-arm64: ./target/aarch64-unknown-linux-gnu/compact/libgrandine.so ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll
ifeq ($(DOCKER_LABEL),)
	@echo "Failed to build docker image - please provide DOCKER_LABEL=, either 'stable' or 'unstable'"
else
	@cp ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll ./target/aarch64-unknown-linux-gnu/compact/
	docker buildx build \
		--file ./bindings/csharp/Grandine.NethermindPlugin/Dockerfile \
		--platform linux/arm64 \
		--build-arg NETHERMIND_VERSION=$(NETHERMIND_VERSION) \
		--push \
		--tag $(DOCKER_REPO):$(DOCKER_LABEL)-arm64$(DOCKER_SUFFIX)-nethermind-$(NETHERMIND_VERSION) \
		./target/aarch64-unknown-linux-gnu/compact
endif

.PHONY: nethermind-docker-amd64
nethermind-docker-amd64: ./target/x86_64-unknown-linux-gnu/compact/libgrandine.so ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll
ifeq ($(DOCKER_LABEL),)
	@echo "Failed to build docker image - please provide DOCKER_LABEL=, either 'stable' or 'unstable'"
else
	@cp ./bindings/csharp/Grandine.NethermindPlugin/bin/Release/net9.0/Grandine.NethermindPlugin.dll ./target/x86_64-unknown-linux-gnu/compact/
	docker buildx build \
		--file ./bindings/csharp/Grandine.NethermindPlugin/Dockerfile \
		--platform linux/amd64 \
		--build-arg NETHERMIND_VERSION=$(NETHERMIND_VERSION) \
		--push \
		--tag $(DOCKER_REPO):$(DOCKER_LABEL)-amd64$(DOCKER_SUFFIX)-nethermind-$(NETHERMIND_VERSION) \
		./target/x86_64-unknown-linux-gnu/compact
endif
