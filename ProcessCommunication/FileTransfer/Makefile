all: sender recv

sender: sender.cpp msg.h
	g++ sender.cpp -o sender

recv: recv.cpp msg.h
	g++ recv.cpp -o recv

clean:
	rm -rf sender recv *.o
