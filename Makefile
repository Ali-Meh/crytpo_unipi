build:
	g++ -o main main.cpp -lssl -lm -lcrypto -l sqlite3 && ./main
	
	
db:
	cd lib && g++ -o main db.cpp -lssl -lm -lcrypto -l sqlite3 && ./main
dh:
	cd lib && g++ -o main dh.cpp -lssl -lm -lcrypto -l sqlite3 && ./main

hash:
	cd lib && g++ -o main hash.cpp -lssl -lm -lcrypto -l sqlite3 && ./main


ser:
	cd server && g++ -o server server.cpp -lssl -lm -lcrypto -l sqlite3 && ./server


cli:
	cd client && g++ -o client client.cpp -lssl -lm -lcrypto -l sqlite3 && ./client
aes:
	cd lib && g++ -o temp AES.cpp -lssl -lm -lcrypto -l sqlite3 && ./temp

ec:
	cd lib && g++ -o temp EC.cpp -lssl -lm -lcrypto -l sqlite3 && ./temp

nc:
	nc localhost 8080

..PHONY: server client aes