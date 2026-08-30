# Makefile — build for the ITB C binding (thin Triple Pipeline proxy).
#
# Targets:
#   all (default):  build/libitb_c.a + build/libitb_c.so + every test binary.
#   libitb.so:      rebuilds the underlying Go shared library into ITB_DIST.
#   test:           builds + runs every tests/test_*.c binary (sequential).
#   test-asan:      the test suite under AddressSanitizer (separate build dir).
#   test-ubsan:     the test suite under UndefinedBehaviorSanitizer.
#   test-valgrind:  the test suite under valgrind --leak-check=full.
#   eitb:           builds the eitb CLI at eitb/eitb.
#   bench:          builds + runs the benches/bench_*.c micro-benchmarks.
#   clean:          removes every generated artefact.
#
# Variables (override on the command line):
#   CC        C compiler                  (default: cc)
#   ITB_DIST  path to libitb.so + .h dir  (default: ../../dist/linux-amd64)

CC         ?= cc
ITB_DIST   ?= ../../dist/linux-amd64
BUILD      ?= build
TESTBUILD  ?= tests/build
BENCHBUILD ?= benches/build
SANFLAGS   ?=
FORTIFY    ?= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2

WARN = -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
       -Wformat=2 -Wnull-dereference -Wmissing-prototypes -Wstrict-prototypes \
       -Wcast-align -Werror

CFLAGS  = -std=c11 -O2 -g $(WARN) $(FORTIFY) -fstack-protector-strong -fPIC \
          -Iinclude -Isrc -isystem $(ITB_DIST) $(SANFLAGS)
RPATH   = $(abspath $(ITB_DIST))
LDFLAGS = -L$(ITB_DIST) -Wl,-rpath,$(RPATH) $(SANFLAGS)
LIBITB  = -litb

# ---- Library ---------------------------------------------------------
LIB_SRCS = src/itb_status.c src/itb_opts.c src/itb_pipeline.c src/itb_stream.c
LIB_OBJS = $(patsubst src/%.c,$(BUILD)/%.o,$(LIB_SRCS))
LIB_HDRS = include/itb.h src/internal.h

all: $(BUILD)/libitb_c.a $(BUILD)/libitb_c.so tests

$(BUILD)/%.o: src/%.c $(LIB_HDRS)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/libitb_c.a: $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

$(BUILD)/libitb_c.so: $(LIB_OBJS)
	$(CC) -shared $(LIB_OBJS) -o $@ $(LDFLAGS) $(LIBITB)

# ---- Underlying Go shared library -----------------------------------
libitb.so:
	cd ../.. && go build -trimpath -buildmode=c-shared \
	    -o dist/linux-amd64/libitb.so ./cmd/cshared

# ---- Tests -----------------------------------------------------------
# Each tests/test_*.c becomes its own binary linked against the static
# library (explicit archive path so the .so next to it is not picked)
# plus libitb.so via embedded RPATH.
TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(patsubst tests/test_%.c,$(TESTBUILD)/test_%,$(TEST_SRCS))

tests: $(BUILD)/libitb_c.a $(TEST_BINS)

$(TESTBUILD)/test_%: tests/test_%.c tests/test_util.h $(BUILD)/libitb_c.a
	@mkdir -p $(TESTBUILD)
	$(CC) $(CFLAGS) -Itests $< $(BUILD)/libitb_c.a -o $@ $(LDFLAGS) $(LIBITB)

test: tests
	@fail=0; \
	for t in $(TEST_BINS); do \
	    if "$$t" >/dev/null 2>&1; then \
	        printf '  ok   %s\n' "$$t"; \
	    else \
	        printf '  FAIL %s\n' "$$t"; "$$t"; fail=1; \
	    fi; \
	done; \
	exit $$fail

test-asan:
	$(MAKE) BUILD=build/asan TESTBUILD=tests/build/asan FORTIFY= \
	    SANFLAGS="-fsanitize=address -fno-omit-frame-pointer" test

test-ubsan:
	$(MAKE) BUILD=build/ubsan TESTBUILD=tests/build/ubsan FORTIFY= \
	    SANFLAGS="-fsanitize=undefined -fno-sanitize-recover=all" test

# The suppression file silences memcheck noise whose faulting frame
# lies inside libitb.so (Go-runtime stack/heap management memcheck
# cannot model); binding-side C frames are never suppressed.
test-valgrind: tests
	@for t in $(TEST_BINS); do \
	    echo "==> valgrind $$t"; \
	    valgrind --leak-check=full --error-exitcode=1 \
	        --errors-for-leak-kinds=definite \
	        --suppressions=tests/valgrind.supp "$$t" >/dev/null || exit 1; \
	done

# ---- Eitb CLI --------------------------------------------------------
eitb: eitb/eitb

eitb/eitb: eitb/eitb.c $(BUILD)/libitb_c.a
	$(CC) $(CFLAGS) eitb/eitb.c $(BUILD)/libitb_c.a -o $@ $(LDFLAGS) $(LIBITB)

# ---- Benches ---------------------------------------------------------
BENCH_SRCS := $(wildcard benches/bench_*.c)
BENCH_BINS := $(patsubst benches/bench_%.c,$(BENCHBUILD)/bench_%,$(BENCH_SRCS))

$(BENCHBUILD)/bench_%: benches/bench_%.c benches/bench_util.h $(BUILD)/libitb_c.a
	@mkdir -p $(BENCHBUILD)
	$(CC) $(CFLAGS) -Ibenches $< $(BUILD)/libitb_c.a -o $@ $(LDFLAGS) $(LIBITB)

bench: $(BENCH_BINS)
	@for b in $(BENCH_BINS); do "$$b" || exit 1; done

# ---- Cleanup ---------------------------------------------------------
clean:
	rm -rf $(BUILD) tests/build benches/build eitb/eitb

.PHONY: all libitb.so tests test test-asan test-ubsan test-valgrind \
        eitb bench clean
