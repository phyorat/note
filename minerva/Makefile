SUB_DIR := $(strip $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST)))))
TOP_DIR := ${SUB_DIR}/..
include $(TOP_DIR)/rules.mk
include $(INCLUDE_DIR)/default.mk

SRC_DIR=src
MAKE_PATH=src
CONFIGURE_PATH=src
BUILD_PATH=$(BUILD_DIR)/minerva

CC:=gcc

EXT_CFLAGS+=-I$(BUILD_DIR)/daq/pkg-install/include
EXT_LDFLAGS+=-L$(BUILD_DIR)/daq/pkg-install/lib

#define values
define Package/minerva
  DEPENDS:=
  #libs/heartbeat
endef

define Package/minerva/Prepare
	@echo "pakcage prepare:"
	-mkdir -p $(BUILD_PATH)
	@if [ ! -d $(BUILD_PATH)/$(MAKE_PATH) ]; then \
		cp -r $(SRC_DIR) $(BUILD_PATH); \
	fi
endef

$(eval $(call BuildPackage,minerva))
