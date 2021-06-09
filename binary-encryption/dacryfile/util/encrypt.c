#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <rc4.h>

#define STRCMP(a, R, b) (strcmp(a, b) R 0)


Elf_Scn * get_scnbyname(Elf *elf, char *name, int *num);
int fatal(char *s);

int
usage(char *s)
{
	printf("%s [file to encrypt]\n", s);
	exit(EXIT_FAILURE);
}

int
main (int argc, char **argv)
{
	Elf64_Phdr	* phdr;
	Elf64_Ehdr	* ehdr;
	rc4_key		  key;
	int		  fd,
			  i = 0,
			  off;
	char		* file = NULL,
			* passw = NULL,
			  pass[256],
			* ptr,
			* buf;
	struct stat	  st;

	if (argc == 2)
		file = argv[1];
	else
		usage(argv[0]);
	do {
		if (i)
			printf("Passphrases don't match.\n");

		if ((passw = getpass("Passphrase: ")) == NULL) 
			fatal("Bad pass");

		memcpy(pass, passw, strlen(passw));

		#if 0
		if ((passw = getpass("Confirm phrase: ")) == NULL)
			fatal("Bad pass");
		i = 1;
		#endif
	} while (0);

	memset(pass, 0x00, sizeof(pass));

	if ((fd = open(file, O_RDWR, 0)) == -1)
		fatal("open host file");

	if (fstat(fd, &st) < 0)
		fatal("stat host file");

	if ((ptr = mmap(NULL, st.st_size, (PROT_READ|PROT_WRITE),
					MAP_SHARED, fd, 0)) == (void *)(-1))
		fatal("mmap failed");

	ehdr = (Elf64_Ehdr *)ptr;
	phdr = (Elf64_Phdr *)(ptr + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++, phdr++)
	{
		if (phdr->p_type == PT_LOAD)
			break;
	}

	off = ehdr->e_entry - phdr->p_vaddr;

	buf = (char *)(ptr + off);

	prepare_key(passw, strlen(passw), &key);
	myrc4(buf, phdr->p_filesz - off, &key);
	munmap(ptr, st.st_size);

	return 0;
}
