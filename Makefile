# Makefile — build for the ITB C binding.
#
# Targets:
#   all (default): builds build/libitb_c.a (the static binding library).
#   tests:         compiles every tests/test_*.c into tests/build/test_*.
#   test:          builds + runs every test (sequential).
#   bench:         compiles bench/bench.c into bench/build/bench.
#   clean:         removes every generated artefact.
#
# The Makefile is intentionally light — POSIX inference rules only, no
# pattern rules. Build output is split: object files live next to their
# .c sources (POSIX `.c.o` inference rule), the static library and test
# binaries land under build/ / tests/build/ / bench/build/.
#
# Variables (override on the command line):
#   CC        C compiler             (default: cc)
#   CSTD      C standard             (default: c17)
#   OPT       optimisation flags     (default: -O2)
#   ITB_DIST  path to libitb.so dir  (default: ../../dist/linux-amd64)

CC       ?= cc
CSTD     ?= c17
OPT      ?= -O2
WARN      = -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
            -Wstrict-prototypes -Wmissing-prototypes
ITB_DIST ?= ../../dist/linux-amd64

CFLAGS   = -std=$(CSTD) $(OPT) $(WARN) -fPIC -Iinclude -Isrc
LDFLAGS  = -L$(ITB_DIST) -Wl,-rpath,$(ITB_DIST)

# Underlying libitb (Go-built c-shared) link.
LIBITB   = -litb

# ---- Library sources (Phase 1-4 today) ------------------------------
LIB_SRCS = \
    src/errors.c \
    src/registry.c \
    src/seed.c \
    src/mac.c \
    src/cipher.c \
    src/encryptor.c \
    src/blob.c \
    src/streams.c
LIB_OBJS = $(LIB_SRCS:.c=.o)

# ---- Default target --------------------------------------------------
all: build/libitb_c.a

# POSIX inference rule for *.c -> *.o.
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

build/libitb_c.a: $(LIB_OBJS)
	mkdir -p build
	$(AR) rcs $@ $(LIB_OBJS)

# ---- Tests (Phase 5 wires individual test_*.c targets here) ---------
# Auto-discover test sources with shell glob; each test_X.c becomes its
# own binary under tests/build/test_X linked against build/libitb_c.a +
# the system check unit-testing framework.
TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(patsubst tests/test_%.c,tests/build/test_%,$(TEST_SRCS))

CHECK_CFLAGS := $(shell pkg-config --cflags check 2>/dev/null)
CHECK_LIBS   := $(shell pkg-config --libs   check 2>/dev/null)

tests: build/libitb_c.a $(TEST_BINS)

# One per-test pattern rule; safe because each test is self-contained.
tests/build/test_%: tests/test_%.c build/libitb_c.a
	mkdir -p tests/build
	$(CC) $(CFLAGS) $(CHECK_CFLAGS) $< -o $@ \
	    -Lbuild -litb_c $(LDFLAGS) $(LIBITB) $(CHECK_LIBS)

test: tests
	@./run_tests.sh

# ---- Bench (Phase 6) ------------------------------------------------
# Each bench/bench_*.c becomes its own binary linked against
# build/libitb_c.a + bench/common.c (shared timing harness, env-var
# parsing, output line emission). The wildcard glob `bench/bench_*.c`
# excludes bench/common.c, which is linked into every bench binary
# rather than producing one of its own.
BENCH_SRCS    := $(wildcard bench/bench_*.c)
BENCH_BINS    := $(patsubst bench/%.c,bench/build/%,$(BENCH_SRCS))
BENCH_COMMON  := bench/common.c
BENCH_HEADERS := bench/common.h

bench: build/libitb_c.a $(BENCH_BINS)

bench/build/%: bench/%.c $(BENCH_COMMON) $(BENCH_HEADERS) build/libitb_c.a
	mkdir -p bench/build
	$(CC) $(CFLAGS) -Ibench $< $(BENCH_COMMON) -o $@ \
	    -Lbuild -litb_c $(LDFLAGS) $(LIBITB)

# ---- Cleanup ---------------------------------------------------------
clean:
	rm -f src/*.o
	rm -rf build tests/build bench/build

.PHONY: all tests test bench clean
