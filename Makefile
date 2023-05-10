build:
	g++ -o main main.cpp -lssl -lm -lcrypto -l sqlite3 && ./main
	
	
db:
	cd lib && g++ -o main db.cpp -lssl -lm -lcrypto -l sqlite3 && ./main

hash:
	cd lib && g++ -o main hash.cpp -lssl -lm -lcrypto -l sqlite3 && ./main


ser:
	cd server && g++ -o server server.cpp -lssl -lm -lcrypto -l sqlite3 && ./server


cli:
	cd client && g++ -o client client.cpp -lssl -lm -lcrypto -l sqlite3 && ./client

..PHONY: server client