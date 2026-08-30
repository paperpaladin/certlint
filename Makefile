# Default target builds; `make test` runs the suite. Keep `all` first: the
# collection's build gate builds the DEFAULT target of every commit.
CARGO ?= cargo

all:
	$(CARGO) build --release --offline

test: all
	sh t/run.sh

clean:
	$(CARGO) clean
	rm -rf t/corpus t/scratch

.PHONY: all test clean mutants overread

mutants: all
	python3 t/mutants.py

# The planted one-past-the-end read. The release profile is panic =
# abort, so the gate wants exit 134, which is SIGABRT and is a status
# this program cannot produce by any other route: a refusal is 1, a
# usage error 2, a chain failure 3 and a lint finding 4.
overread: all
	$(CARGO) build --release --offline --features plant_overread \
	    --target-dir target/overread
	sh t/overread.sh
