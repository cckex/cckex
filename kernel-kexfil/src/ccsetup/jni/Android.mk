LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE	:= ccsetup
LOCAL_CFLAGS 	:= -std=c++20 
LOCAL_SRC_FILES := ccsetup.cc
LOCAL_LDLIBS 	:= -llog

include $(BUILD_EXECUTABLE)
