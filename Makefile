#BUILDMAKE edit-mode: -*- Makefile -*-
####################64Bit Mode####################
ifeq ($(shell uname -m), x86_64)
CC=gcc
CXX=g++
CXXFLAGS=-g \
  -O2 \
  -pipe \
  -W \
  -Wall \
  -fPIC \
  -std=c++11
CFLAGS=-g \
  -pipe \
  -W \
  -Wall \
  -fPIC
CPPFLAGS=-D_GNU_SOURCE \
  -D__STDC_LIMIT_MACROS \
  -DVERSION=\"1.9.8.7\"
INCPATH=-I. \
  -I./include
DEP_INCPATH=

.PHONY:all
all:nurse 
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;31;40mall[0m']"
	@echo "make all done"

.PHONY:clean
clean:
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;31;40mclean[0m']"
	rm -rf nurse
	rm -rf ./output/bin/nurse
	rm -rf nurse_main.o

nurse:nurse_main.o 
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;31;40mnurse[0m']"
	$(CXX) nurse_main.o -Xlinker "-(" -lcurl -lpthread -lrt -Xlinker "-)" -o nurse

nurse_main.o:main.cpp \
  include/health_state.hpp \
  include/thread_pool.hpp \
  include/host_prob.hpp \
  include/thread_pool.hpp
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;31;40mnurse_main.o[0m']"
	$(CXX) -c $(INCPATH) $(DEP_INCPATH) $(CPPFLAGS) $(CXXFLAGS)  -o nurse_main.o main.cpp

endif #ifeq ($(shell uname -m), x86_64)


