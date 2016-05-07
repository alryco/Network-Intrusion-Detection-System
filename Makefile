all: desman watchdog

CC = g++
LFLAGS = -Wall -std=c++11 -lpcap -lpthread
CFLAGS = -Wall -std=c++11 -c


# ****** DESMAN ******

desman: connection_manager.o src/desman/main.cpp
	$(CC) -o desman connection_manager.o src/desman/main.cpp $(LFLAGS)

connection_manager.o: src/desman/connection_manager.cpp src/desman/connection_manager.h
	$(CC) $(CFLAGS) src/desman/connection_manager.cpp



# ****** WATCHDOG ******

watchdog: traffic_analyzer.o src/watchdog/main.cpp
	$(CC) -o watchdog traffic_analyzer.o src/watchdog/main.cpp $(LFLAGS)

traffic_analyzer.o: src/watchdog/traffic_analyzer.cpp src/watchdog/traffic_analyzer.h src/watchdog/network_protocols.h
	$(CC) $(CFLAGS) src/watchdog/traffic_analyzer.cpp



clean:
	$(RM) desman watchdog *.o *~

