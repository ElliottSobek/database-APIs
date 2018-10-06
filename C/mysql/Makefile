SHELL := /bin/bash

CC := gcc

CFLAGS := -Wall -Wextra -Werror -Wno-unused-parameter -std=c99

LDLIBS :=

OBJECTS := mysql.o

ifeq ($(MAKECMDGOALS),)
override CFLAGS += -g
else ifeq ($(MAKECMDGOALS),debug)
override CFLAGS += -g
else ifeq ($(MAKECMDGOALS),profile)
override CFLAGS += -pg
else
override CFLAGS += -O3
endif

.PHONY: debug profile production clean

debug: $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o mysql_api

profile: $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o mysql_api

production: $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o mysql_api

$(OBJECTS):

clean:
	$(RM) *.o
