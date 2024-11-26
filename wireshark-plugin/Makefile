.PHONY: init reset build clean

VERBOSE ?= @

# binaries
DOCKER = docker

# directories and files
WIRESHARK_DIR = $(shell pwd)/wireshark
WIRESHARK_PLUGIN_DIR = $(WIRESHARK_DIR)/plugins/epan
WIRESHARK_BUILD_DIR =$(WIRESHARK_DIR)/build
CCKEX_SRC_DIR = $(shell pwd)/src

PATCHFILE = $(shell pwd)/wireshark.patch

init: 	## Initialize the cckex wireshark docker build container
	@echo "INIT 	container"
	$(VERBOSE) $(DOCKER) compose build
	@echo "INIT		build-env"
	$(VERBOSE) $(DOCKER) compose run --service-ports --rm \
		cckex_wireshark /init-entrypoint.sh

init_wireshark: 	## Initialize the wireshark build environment with the ccKex Plugin (in the current context)
	@echo "GIT 		fetch repo"
	-$(VERBOSE) git clone --branch release-4.2 https://gitlab.com/wireshark/wireshark.git $(WIRESHARK_DIR) || true
	@echo "GIT		apply patch to Wireshark"
	-$(VERBOSE) cd $(WIRESHARK_DIR); git apply $(PATCHFILE)
	@echo "LINK		$(WIRESHARK_PLUGIN_DIR)/ccKex -> $(CCKEX_SRC_DIR)"
	-$(VERBOSE) cd $(WIRESHARK_PLUGIN_DIR); ln -fns $(CCKEX_SRC_DIR) ccKex
	@echo "CMAKE	Wireshark"
	$(VERBOSE) mkdir -p $(WIRESHARK_BUILD_DIR)
	$(VERBOSE) cd $(WIRESHARK_BUILD_DIR); cmake .. -DCUSTOM_PLUGIN_SRC_DIR="$(WIRESHARK_PLUGIN_DIR)/ccKex"

build: 	## Build wireshark with the ccKex Plugin (in the docker container)
	@echo "BUILD	wireshark"
	$(VERBOSE) $(DOCKER) compose run --service-ports --rm \
		cckex_wireshark /build-entrypoint.sh
build_wireshark: 	## Build Wireshark with the ccKex Plugin (in the current context)
	@echo "MAKE 	Wireshark"
	$(VERBOSE) $(MAKE) -C $(WIRESHARK_BUILD_DIR)

clean: 	## Clean all build files
	@echo "MAKE 	clean Wireshark"
	$(VERBOSE) $(MAKE) -C $(WIRESHARK_BUILD_DIR) clean

reset: 	## Reset the wireshark-plugin subfolder to it's initial state
	@echo "GIT 		restore Wireshark"
	$(VERBOSE) cd $(WIRESHARK_DIR); git restore .
	@echo "GIT 		clean Wireshark"
	$(VERBOSE) cd $(WIRESHARK_DIR); git clean -fdx .

run-shell: 	## Run the docker container and drop into a shell
	$(DOCKER) compose run -v $(XAUTHORITY):/root/.Xauthority:ro -e DISPLAY=$(DISPLAY) -e XAUTHORITY=/root/.Xauthority --service-ports --rm \
		cckex_wireshark /bin/bash

# custom help target
help: ## Show this help
	@grep -hE '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

define print_set_variable_hint
	$(if $(filter $(1),""), @echo "Hint: Set $(2) to call the Makefile with additional flags / variables.")
endef
	
