# Définition des variables
CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lcapstone
SRC = ./src/main.c
TARGET = ./bin/bench
BIN_DIR = ./bin
EXECUTABLE = /bin/ls
OUTPUT_FILE = ./logs/trace.log

# Règle par défaut
all: $(TARGET)

# Création du dossier bin si nécessaire et compilation
$(TARGET): $(SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Règle pour créer le dossier bin
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Nettoyage
clean:
	rm -f $(TARGET)

# Nettoyage complet (supprime aussi le dossier bin)
distclean: clean
	rm -rf $(BIN_DIR)

.PHONY: all clean distclean
