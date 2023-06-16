CPUS=$(shell cat /proc/cpuinfo | grep "processor" | wc -l)
PWD=$(shell pwd)
BUILD_DIR=$(PWD)/build
MAKE_OPT=

define shcmd-makepre
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake ..
endef

define shcmd-make
	@cd $(BUILD_DIR) && make -j$(CPUS) $(MAKE_OPT) | grep -v "^make\[[0-9]\]:"
endef

define shcmd-makeclean
	@if [ -d $(BUILD_DIR) ]; then (cd $(BUILD_DIR) && make clean && echo "##Clean build##"); fi
endef

define shcmd-makerm
	@if [ -d $(BUILD_DIR) ]; then (rm -rf $(BUILD_DIR)); fi
endef

.PHONY: all clean rm pre
all: pre
	$(call shcmd-make)

clean:
	$(call shcmd-makeclean)

rm:
	$(call shcmd-makerm)

pre:
	$(call shcmd-makepre)
