# 定义要编译的子目录列表
KERNEL_KO_SRC_DIR := tipc-1.7.7/net/tipc
TEST_SRC_DIR := tipcutils-1.1.9/test_tipc
CONFIG_SRC_DIR := tipcutils-1.1.9/tipc_config

export ETIPC_ROOT_PATH=$(shell pwd)
export ETIPC_INCLUDE_PATH=$(ETIPC_ROOT_PATH)/tipc-1.7.7/include

SUBDIRS := $(KERNEL_KO_SRC_DIR) $(TEST_SRC_DIR) $(CONFIG_SRC_DIR)

# 默认目标
all:
	@for dir in $(SUBDIRS); do \
		echo "Building in $$dir"; \
		$(MAKE) -C $$dir all; \
		if [ $$? -ne 0 ]; then \
			echo "Build failed in $$dir"; \
			exit 1; \
		fi; \
	done

# 清理目标
clean:
	rm -rf tipc.ko
	@for dir in $(SUBDIRS); do \
		echo "Cleaning in $$dir"; \
		$(MAKE) -C $$dir clean; \
	done

# 安装规则
ifndef INSTALL_LIB
INSTALL_LIB = ./
endif
ifndef INCLUDE_PATH
INCLUDE_PATH = ./
endif
install:
	mkdir -p $(INSTALL_LIB)
	mkdir -p $(INCLUDE_PATH)
	cp $(KERNEL_KO_SRC_DIR)/tipc.ko $(INSTALL_LIB)
	cp $(CONFIG_SRC_DIR)/tipc_config $(INSTALL_LIB)
	cp $(TEST_SRC_DIR)/recv $(INSTALL_LIB)
	cp $(TEST_SRC_DIR)/usend $(INSTALL_LIB)
	cp $(TEST_SRC_DIR)/msend $(INSTALL_LIB)
	cp -rf $(ETIPC_INCLUDE_PATH)/* $(INCLUDE_PATH)

# 避免make默认规则
.PHONY: all clean