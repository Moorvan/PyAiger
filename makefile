aiger: aiger.c aiger.h
	gcc -shared -fPIC -o libaiger.so aiger.c aiger.h