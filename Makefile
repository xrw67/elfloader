all:
	gcc -Wall -g -o elfloader elf_loader.c main.c wheelc/list.c -ldl -lpthread

clean:
	rm -rf *.o wheelc/*.o elfloader

