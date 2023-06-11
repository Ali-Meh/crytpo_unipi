build:
	g++ -o main main.cpp -lssl -lm -lcrypto -l sqlite3 && ./main

clear:
	clear
	
db:
	cd lib && g++ -o main db.cpp -lssl -lm -lcrypto -l sqlite3 && ./main
dh:
	cd lib && g++ -o main dh.cpp -lssl -lm -lcrypto -l sqlite3 && ./main

hash:
	cd lib && g++ -o main hash.cpp -lssl -lm -lcrypto -l sqlite3 && ./main


ser:clear
	cd server && g++ -o server server.cpp -lssl -lm -lcrypto -l sqlite3 && ./server


cli:clear
	cd client && g++ -o client client.cpp -lssl -lm -lcrypto -l sqlite3 && ./client
aes:
	cd lib && g++ -o temp AES.cpp -lssl -lm -lcrypto -l sqlite3 && ./temp

ec:
	cd lib && g++ -o temp EC.cpp -lssl -lm -lcrypto -l sqlite3 && ./temp

nc:
	nc localhost 8080


sercheck:
	cd server && g++ -o server server.cpp -lssl -lm -lcrypto -l sqlite3 -ggdb3 && valgrind --leak-check=full \
			--show-leak-kinds=all \
			--track-origins=yes \
			--verbose \
			--log-file=valgrind-out.txt ./server

clicheck:
	cd client && g++ -o client client.cpp -lssl -lm -lcrypto -l sqlite3 -ggdb3 && valgrind --leak-check=full \
			--show-leak-kinds=all \
			--track-origins=yes \
			--verbose \
			--log-file=valgrind-out.txt ./client


..PHONY: server client aes