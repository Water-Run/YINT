# yint-core / yint CLI -- portable Makefile.
#
# Targets:
#   make             # native build (default)
#   make linux       # native Linux (gcc/clang)
#   make macos       # macOS, dual-arch (arm64 + x86_64)
#   make win32-xp    # i686-w64-mingw32, runs on Windows XP through 11
#   make win64       # x86_64-w64-mingw32
#   make test        # build + run yint-test.lua
#   make clean

YINT_VERSION ?= 1.0.0
BIN          ?= yint
EXE_SUFFIX   ?=

CC      ?= cc
AR      ?= ar
STRIP   ?= strip
LUA     ?= lua

# Detect host architecture for AES-NI inclusion.
UNAME_M := $(shell uname -m 2>/dev/null)
IS_X86  := $(filter $(UNAME_M),x86_64 amd64 i386 i686)

CFLAGS_COMMON  := -O2 -std=c99 -Wall -Wextra -Wpedantic \
                  -fno-strict-aliasing -fvisibility=hidden
CFLAGS_AESNI   := -maes -msse4.1
LDFLAGS_COMMON :=
LDLIBS_COMMON  :=

CFLAGS  ?= $(CFLAGS_COMMON)
LDFLAGS ?= $(LDFLAGS_COMMON)
LDLIBS  ?= $(LDLIBS_COMMON)

CORE_SRCS := yint-core.c
ifeq ($(strip $(IS_X86)),)
  AESNI_OBJS :=
else
  AESNI_OBJS := yint-aesni.o
endif

CORE_OBJS := yint-core.o $(AESNI_OBJS)
CLI_OBJS  := yint-cli.o $(CORE_OBJS)

.PHONY: all native linux macos win32-xp win64 test clean

all: native

native: $(BIN)$(EXE_SUFFIX)

$(BIN)$(EXE_SUFFIX): $(CLI_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

yint-core.o: yint-core.c yint-core.h
	$(CC) $(CFLAGS) -c -o $@ $<

yint-aesni.o: yint-aesni.c yint-core.h
	$(CC) $(CFLAGS) $(CFLAGS_AESNI) -c -o $@ $<

yint-cli.o: yint-cli.c yint-core.h
	$(CC) $(CFLAGS) -c -o $@ $<

linux:
	$(MAKE) native CC=$(CC) CFLAGS="$(CFLAGS_COMMON)"

macos:
	$(MAKE) native CC=clang \
	    CFLAGS="$(CFLAGS_COMMON) -arch arm64 -arch x86_64 -mmacosx-version-min=11.0" \
	    LDFLAGS="-arch arm64 -arch x86_64"

# WinXP-compatible 32-bit. Static link, target Windows 5.1.
win32-xp:
	$(MAKE) native \
	    CC=i686-w64-mingw32-gcc \
	    EXE_SUFFIX=.exe \
	    CFLAGS="$(CFLAGS_COMMON) -D_WIN32_WINNT=0x0501 -DWINVER=0x0501" \
	    LDFLAGS="-static" \
	    LDLIBS="-ladvapi32"

win64:
	$(MAKE) native \
	    CC=x86_64-w64-mingw32-gcc \
	    EXE_SUFFIX=.exe \
	    CFLAGS="$(CFLAGS_COMMON)" \
	    LDFLAGS="-static" \
	    LDLIBS="-ladvapi32"

test: native
	$(LUA) yint-test.lua

clean:
	rm -f *.o $(BIN) $(BIN).exe
