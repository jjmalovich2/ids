CC = g++
CFLAGS = -Wall -O2
LIBS = -lpcap
TARGET = ids
SOURCES = main.cpp aho_corasick.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LIBS)
	@echo "Adding permissions"
	sudo setcap cap_net_raw,cap_net_admin=eip $(TARGET)

clean:
	rm -f $(TARGET)