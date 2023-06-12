CC = g++
CFLAGS = -Wall -g
LDFLAGS = -lm -lcrypto -lsqlite3
OPT = -ggdb3

clear:
	clear

server-compile:
	cd server && $(CC) $(CFLAGS) -o server server.cpp $(LDFLAGS) 
srv:clear server-compile
	cd server && ./server


client-compile:
	cd client && $(CC) $(CFLAGS) -o client client.cpp $(LDFLAGS)
cli:clear client-compile
	cd client && ./client

build:
	$(CC) $(CFLAGS) -o main main.cpp $(LDFLAGS)  && ./main
# db:
# 	cd lib && g++ -o main db.cpp -lssl -lm -lcrypto -l sqlite3 && ./main
# dh:
# 	cd lib && g++ -o main dh.cpp -lssl -lm -lcrypto -l sqlite3 && ./main

# hash:
# 	cd lib && g++ -o main hash.cpp -lssl -lm -lcrypto -l sqlite3 && ./main



# aes:
# 	cd lib && g++ -o temp AES.cpp -lssl -lm -lcrypto -l sqlite3 && ./temp

# ec:
# 	cd lib && g++ -o temp EC.cpp -lssl -lm -lcrypto -l sqlite3 && ./temp

# nc:
# 	nc localhost 8080


srvcheck:server-compile
	cd server && valgrind --leak-check=full \
			--show-leak-kinds=all \
			--track-origins=yes \
			--verbose \
			--log-file=valgrind-out.txt ./server

clicheck:client-compile
	cd client && valgrind --leak-check=full \
			--show-leak-kinds=all \
			--track-origins=yes \
			--verbose \
			--log-file=valgrind-out.txt ./client


..PHONY: server client aes clear