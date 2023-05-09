build:
	g++ -o main main.cpp -lssl -lm -lcrypto -l sqlite3 && ./main
	
	
db:
	cd lib && g++ -o main db.cpp -lssl -lm -lcrypto -l sqlite3 && ./main

hash:
	cd lib && g++ -o main hash.cpp -lssl -lm -lcrypto -l sqlite3 && ./main