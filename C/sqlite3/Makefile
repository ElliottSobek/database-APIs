SHELL := /bin/bash

CC := gcc

CFLAGS := -Wall -Wextra -Werror -std=c99 -D_POSIX_C_SOURCE=200809L

LDLIBS := -lsqlite3

OBJECTS := sqlite3.o

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
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o sqlite3_api

profile: $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o sqlite3_api

production: $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o sqlite3_api

$(OBJECTS):

clean:
	$(RM) *.o
