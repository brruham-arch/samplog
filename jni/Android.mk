LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := samplog
# Output: libsamplog.so

LOCAL_SRC_FILES := \
    ../main.cpp

LOCAL_CPPFLAGS := \
    -std=c++17 \
    -O2 \
    -fvisibility=hidden \
    -ffunction-sections \
    -fdata-sections

LOCAL_LDLIBS := \
    -llog \
    -lm \
    -ldl

LOCAL_LDFLAGS := \
    -static-libstdc++ \
    -Wl,--gc-sections

include $(BUILD_SHARED_LIBRARY)