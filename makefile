CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -I./
LDLIBS  := -lssl -lcrypto -luuid
 
BUILD   := build

UTIL_SRCS   := $(wildcard utils/*.c)
SERVER_SRCS := $(wildcard server/*.c)
CLIENT_SRCS := $(wildcard client/*.c)
TEST_MAIN_SRC := main.c

TEST_MAIN_OBJS   := $(patsubst %.c,$(BUILD)/%.o,$(TEST_MAIN_SRC))

UTIL_OBJS   := $(patsubst %.c,$(BUILD)/%.o,$(UTIL_SRCS))
SERVER_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(SERVER_SRCS))
CLIENT_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(CLIENT_SRCS))

SERVER_EXE  := $(BUILD)/server_main
CLIENT_EXE  := $(BUILD)/client_main
TEST_MAIN := $(BUILD)/test_main

.PHONY: all clean directories run 

all: directories $(SERVER_EXE) $(CLIENT_EXE)

# Create directory tree in build/
directories:
	mkdir -p $(BUILD)/utils $(BUILD)/server $(BUILD)/client

$(SERVER_EXE): $(SERVER_OBJS) $(UTIL_OBJS)
	$(CC) $^ -o $@ $(LDLIBS)

$(CLIENT_EXE): $(CLIENT_OBJS) $(UTIL_OBJS)
	$(CC) $^ -o $@ $(LDLIBS)

$(TEST_MAIN): $(TEST_MAIN_OBJS)
	$(CC) $^ -o $@ $(LDLIBS)


# Compile .c → build/.../.o
$(BUILD)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD)
run: all 
	@echo "Starting server..."
	@$(SERVER_EXE) & \
	SERVER_PID=$$!; \
	sleep 1; \
	echo "Starting client..."; \
	$(CLIENT_EXE); \
	echo "Stopping server..."; \
	kill $$SERVER_PID

test: $(TEST_MAIN)
	$(TEST_MAIN);

run-s: all
	$(SERVER_EXE);
run-c: all
	$(CLIENT_EXE);
