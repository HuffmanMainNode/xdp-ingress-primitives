CLANG ?= clang
BPF_CFLAGS ?= -target bpf -O2 -g -Wall -Werror
OUTPUT ?= xdp_ingress.o

.PHONY: all clean test

all: $(OUTPUT)

$(OUTPUT): xdp_ingress.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

test:
	python3 -m unittest discover -v

clean:
	rm -f $(OUTPUT)
