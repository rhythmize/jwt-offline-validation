SRC_DIR=./src
TARGET_DIR=./bin
OBJ_DIR=./obj
TARGET=verifyToken

CC=g++
CFLAGS=-std=c++14 -Iinclude -Ijwt-cpp/include -fsanitize=leak,address -Wall -Wpedantic -fuse-ld=gold
LDFLAGS=`pkg-config --libs openssl`

SOURCES:=$(wildcard $(SRC_DIR)/*.cpp)
OBJECTS:=$(SOURCES:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(info [+] Compiling source $< into $@...)
	@mkdir -p $(OBJ_DIR)
	@$(CC) $(CFLAGS) -c $< -o $@

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS)
	$(info [+] Building $(TARGET)...)
	@mkdir -p $(TARGET_DIR)
	@$(CC) $(CFLAGS) $(OBJECTS) -o $(TARGET_DIR)/$@ $(LDFLAGS)

run: $(TARGET)
	$(info [+] Running $(TARGET)...)
	$(info ---) 
	@$(TARGET_DIR)/$(TARGET)

clean:
	@rm -rf $(OBJ_DIR)
	@rm -rf $(TARGET_DIR)
	$(info [+] Clean done...)
