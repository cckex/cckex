.PHONY: clean build

VERBOSE ?= @

TARGET = ccsetup

NDK_BUILD = /opt/android-ndk/ndk-build

.DEFAULT_GOAL = build

build:
	@echo "BUILD		$(TARGET)"
	$(VERBOSE) $(NDK_BUILD)

clean:
	@echo "RM			$(TARGET)"
	$(VERBOSE) -rm -rf $(TARGET)

