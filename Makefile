CXXFLAGS=-Wall -fPIC
CXXOPT ?= -O3
CC ?= gcc
CXX ?= g++

all: release debug omp aio
test: unit_test

release: CXXFLAGS+=-DNDEBUG $(CXXOPT)
release: iotrap_rel.so
	strip iotrap_rel.so

omp: CXXFLAGS+=-fopenmp $(CXXOPT)
omp: iotrap_omp.so
	strip iotrap_omp.so

debug: CXXFLAGS+=-O0 -g
debug: iotrap_dbg.so

unit_test: CXXFLAGS+=-DUNIT_TEST

iotrap_rel.so iotrap_dbg.so iotrap_omp.so: Makefile hook.cc setup.cc
	$(CXX) $(CXXFLAGS) -ldl -lrt -lpthread -shared -o $@ hook.cc setup.cc

aio unit_test: Makefile aio.cpp
	$(CXX) $(CXXFLAGS) -lrt aio.cpp -o $@

Makefile:

clean:
	@echo Cleaning up shared objects
	@rm -f aio unit_test iotrap_*.so