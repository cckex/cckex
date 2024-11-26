DOCKER 	:= docker
ADB 	:= adb

ANDROID_WORKDIR := /sdcard/Download

.PHONY: build

help: ## Show this help
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

init: build run-setup ## Init the Docker container and setup build environment + emulator

build: compose.yaml ## Build the Docker container(s)
	$(DOCKER) compose build
	
run-setup: ## Run the Docker container
	$(DOCKER) compose run --service-ports --rm \
		kernel-kex-demo /setup-entrypoint.sh
		
run-recompile: ## Run the Docker container
	$(DOCKER) compose run --service-ports --rm \
		kernel-kex-demo /recompile-entrypoint.sh

run-pixel: ## Run the Docker container and build a aarch64 kernel
	$(DOCKER) compose run --service-ports --rm \
		kernel-kex-demo /aarch64-build-entrypoint.sh

run-shell: ## Run the Docker container and drop into a shell
	$(DOCKER) compose run --service-ports --rm \
		kernel-kex-demo /bin/bash

run-demo: ## Run the CCKex Demo Mode in the Docker container
	$(DOCKER) compose run --service-ports --rm \
		kernel-kex-demo /demo-entrypoint.sh

run-setup-hw: ## Setup the Docker container for HW Pixel Kernel Builds
	$(DOCKER) compose run --service-ports --rm \
		kernel-kex-demo /setup-hw-entrypoint.sh

run-recompile-hw: ## Recompile the Pixel Kernel
	$(DOCKER) compose run --service-ports --rm \
		kernel-kex-demo /recompile-hw-entrypoint.sh

#flash: ## Flash built kernel onto real Device

stage-secmonsmash:
	$(ADB) push src/pixel_kernel/out/mixed/dist/secmonsmash.ko $(ANDROID_WORKDIR)
	-$(ADB) shell 'su -c "rmmod $(ANDROID_WORKDIR)/secmonsmash.ko"'
	$(ADB) shell 'su -c "insmod $(ANDROID_WORKDIR)/secmonsmash.ko"'

secmonsmash: run-recompile-hw stage-secmonsmash
