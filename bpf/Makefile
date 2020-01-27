CLANG = clang
CLANG_FLAGS = -O2 -g -Wall -target bpf

RM = rm -f
STATIK = statik
STATIK_OPTS=-include=*.o
TRACE = sudo trace-cmd record -e 'xdp:*' -O trace_printk
VIEW_TRACE = kernelstack trace.dat

OBJ_DIR=objects
OBJS = firewall.o
SRCS = $(OBJS:%.o=%.c)

INCLUDES = -I./include
INCLUDES += -I./libbpf

WORKDIR = $(shell pwd)

default: statik

$(OBJS): $(SRCS)
	$(CLANG) $(CLANG_FLAGS) $(INCLUDES) -c $(SRCS) -o $(OBJ_DIR)/$(OBJS)

statik: $(OBJS)
	$(STATIK) -src=$(OBJ_DIR) $(STATIK_OPTS)
.PHONY: statik

clean:
	$(RM) $(OBJS)
.PHONY: clean

trace:
	$(TRACE)
.PHONY: trace

viewtrace:
	$(VIEW_TRACE)
.PHONY: viewtrace

test: $(WORKDIR)/*.go
	@for file in $^; do \
		sudo go test -v $${file} ; \
	done
.PHONY: test