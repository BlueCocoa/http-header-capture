CXX = g++

PREFIX ?= /usr/local
SOURCE = main.cpp
TARGET = httpc

LDFLAGS += -L/usr/local/lib -lpcap

$(TARGET) : 
	$(CXX) $(LDFLAGS) -I./xterm256 -std=c++14 -fPIC $(SOURCE) -o $(TARGET)
    
install :
	install -m 775 $(TARGET) $(PREFIX)/bin

uninstall :
	rm -f $(PREFIX)/bin

clean :
	-rm -f $(TARGET)
