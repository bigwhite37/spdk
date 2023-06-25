#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2018 Intel Corporation.
#  All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk

APP = hello_raft

C_SRCS = hello_raft.c
C_SRCS += tpl/tpl.c
C_SRCS += raft/raft_log.c raft/raft_node.c raft/raft_server_properties.c raft/raft_server.c

SPDK_LIB_LIST = $(ALL_MODULES_LIST)
SPDK_LIB_LIST += event sock

include $(SPDK_ROOT_DIR)/mk/spdk.app.mk
