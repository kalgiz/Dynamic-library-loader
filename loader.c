#include "loader.h"
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>

#define NONSFI_PAGE_SIZE 0x1000
#define NONSFI_PAGE_MASK (NONSFI_PAGE_SIZE - 1)

struct library 
{
	void *eMap;
	char *strings;
	Elf32_Sym *symbols;
	int symSize;
	void *(*getsym)(const char *name);
	Elf32_Rel *relPlt;
};

//sprawdzanie czy symbol jest typu obsługiwanego przez nas
int isValidSymbol(Elf32_Sym *sym)
{
	return (ELF32_ST_TYPE(sym -> st_info) == STT_NOTYPE || 
		ELF32_ST_TYPE(sym -> st_info) == STT_FUNC ||
		ELF32_ST_TYPE(sym -> st_info) == STT_OBJECT) &&
		(sym -> st_shndx < SHN_LORESERVE ||
		sym -> st_shndx != SHN_ABS);
}

//obliczanie potrzebnej do zamapowania pamięci
size_t countMemSize(Elf32_Phdr * phdr, int phNum)
{
	int i = phNum;
	while ( i >= 0 && phdr[i].p_type != PT_LOAD)
		i--; 
	if (i < 0) 
		return 0;
	return phdr[i].p_vaddr + phdr[i].p_memsz;
}

//sprawdzanie poprawności nagłówka
int checkElfHeader(Elf32_Ehdr *ehdr) 
{
	if (memcmp(ehdr -> e_ident, ELFMAG, SELFMAG) != 0) 
	{
		printf ("Not an ELF file: no ELF header\n");
		return 0;
	}
	if (ehdr -> e_ident[EI_CLASS] != ELFCLASS32) 
	{
		printf ("Unexpected ELF class: not ELFCLASS32\n");
		return 0;
	}
	if (ehdr -> e_ident[EI_DATA] != ELFDATA2LSB)
	{
		printf ("Not a little-endian ELF file\n");
		return 0;
	}
	if (ehdr -> e_type != ET_DYN) 
	{
		printf ("Not a relocatable ELF object (not ET_DYN)\n");
		return 0;
	}
	if (ehdr -> e_machine != EM_386) 
	{
		printf ("Unexpected ELF e_machine field\n");
		return 0;
	}
	if (ehdr -> e_version != EV_CURRENT) 
	{
		printf ("Unexpected ELF e_version field\n");
		return 0;
	}
	if (ehdr -> e_ehsize != sizeof(*ehdr)) 
	{
		printf ("Unexpected ELF e_ehsize field\n");
		return 0;
	}
	if (ehdr -> e_phentsize != sizeof(Elf32_Phdr)) 
	{
		printf ("Unexpected ELF e_phentsize field\n");
		return 0;
	}
	if (ehdr -> e_ident[EI_MAG0] != ELFMAG0 
		|| ehdr -> e_ident[EI_MAG1] != ELFMAG1 
		|| ehdr -> e_ident[EI_MAG2] != ELFMAG2
		|| ehdr -> e_ident[EI_MAG3] != ELFMAG3)
	{
		printf ("Invalid magic numbers\n");
		return 0;
	}
	return 1;
}

//wyrównywanie strony
uintptr_t pageSizeRoundDown(uintptr_t addr) 
{
	return addr & ~NONSFI_PAGE_MASK;
}

uintptr_t pageSizeRoundUp(uintptr_t addr) 
{
	return pageSizeRoundDown(addr + NONSFI_PAGE_SIZE - 1);
}

//odczytywanie uprawnień segmentu
int checkElfFlags(Elf32_Word pflags)
{
	return ((pflags & PF_X) != 0 ? PROT_EXEC : 0) |
		((pflags & PF_R) != 0 ? PROT_READ : 0) |
		((pflags & PF_W) != 0 ? PROT_WRITE : 0);
}

struct library *library_load(const char *name, void *(*getsym)(const char *name))
{
	int i = 0;
	void *buffer;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	struct library *lib = malloc( sizeof (struct library) );
	
	//wczytywanie pliku elf
	lib -> getsym = getsym;
	FILE * file = fopen(name, "r");
	if (file == NULL)
	{
		free(lib);
		perror("Error");
		return NULL;
	}
	//sprawdzanie rozmiaru pliku
	int prev = ftell(file);
	fseek(file, 0L, SEEK_END);
	int fsize = ftell(file);
	fseek(file, prev, SEEK_SET);
	
	//alokowanie pamięci na cały plik
	buffer = malloc(fsize);
	size_t bytes = fread(buffer, 1, fsize, file);
	if (bytes != fsize)
	{
		free(lib);
		free(buffer);
		perror("Error");
		return NULL;
	}
	if (fclose(file) != 0)
	{
		free(lib);
		free(buffer);
		perror("Error");
		return NULL;
	}
	
	
	ehdr = (Elf32_Ehdr *) buffer;
	
	//sprawdzanie nagłówka
	if (!checkElfHeader(ehdr))
	{
		printf("Invalid format of file\n");
		free(buffer);
		free(lib);
		return NULL;
	}
	
	//rzutowanie zawartosci bufora na program header
	phdr = (Elf32_Phdr *)(buffer + ehdr -> e_phoff);
	
	size_t memSize = countMemSize(phdr, ehdr -> e_phnum);
	if (memSize == 0)
	{
		printf ("No PT_LOAD segments.\n");
		free(buffer);
		free(lib);
		return NULL;
	}
	
	//zamapowanie pustego obszaru
	lib -> eMap = mmap(NULL, memSize, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE,
                       -1, 0);
	if (lib -> eMap == MAP_FAILED)
	{
		printf("Mmap failed.\n");
		free(buffer);
		free(lib);
		return NULL;
	}
	
	for (i = 0; i < ehdr -> e_phnum; i++) 
	{
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_filesz)
		{
		//ładowanie do pamięci segmentu LOAD
			if (loadSegment(&phdr[i], lib -> eMap, name) != 0)
			{
				free(buffer);
				munmap(lib -> eMap, memSize);
				free(lib);
				return NULL;
			}
		}
		if (phdr[i].p_type == PT_DYNAMIC)
		{
		//parsowanie segmentu DYNAMIC
			Elf32_Dyn * dyn = (Elf32_Dyn *) (buffer + phdr[i].p_offset);
			if (loadDynamic(buffer, dyn, phdr[i].p_filesz, lib) != 0)
			{
				free(buffer);
				munmap(lib -> eMap, memSize);
				free(lib);
				return NULL;
			}
		}
	}
	
	//przywracanie odpowiednich uprawnień segmentom
	for (i = 0; i < ehdr -> e_phnum; i++) 
	{
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_filesz)
		{
			if (setProt(&phdr[i], lib -> eMap) != 0)
			{
				free(buffer);
				munmap(lib -> eMap, memSize);
				free(lib);
				return NULL;
			}
		}
	}
	
	
	return lib;
}

//ustawianie uprawnień segmentów
int setProt(Elf32_Phdr *phdr, void *dest)
{
	uintptr_t segmentStart = pageSizeRoundDown(phdr -> p_vaddr);
	uintptr_t segmentEnd = pageSizeRoundUp(phdr -> p_vaddr + phdr -> p_memsz);
	void *segmentAddr = (void *) ((uintptr_t) dest + segmentStart);
	int prot = checkElfFlags(phdr -> p_flags);
	if (mprotect(segmentAddr, segmentEnd - segmentStart, prot) == -1)
	{
		printf("Mprotect for segment failed.\n");
		return 1;
	}
	return 0;
}

//ładowanie segmentu typu PT_LOAD
int loadSegment(Elf32_Phdr *phdr, void *dest, const char *name)
{
	if(phdr -> p_filesz > phdr -> p_memsz) 
	{
		printf("Error: p_filesz > p_memsz\n");
		return 1;
	}
	uintptr_t segmentStart = pageSizeRoundDown(phdr -> p_vaddr);
	uintptr_t segmentEnd = pageSizeRoundUp(phdr -> p_vaddr + phdr -> p_memsz);
	void *segmentAddr = (void *) (dest + segmentStart);
	int fd = open (name, O_RDONLY);
	if (fd == -1)
	{
		printf("Cannot open file.\n");
		return 1;
	}
	void *mapResult = mmap(segmentAddr, segmentEnd - segmentStart,
		PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, 
		pageSizeRoundDown(phdr -> p_offset));
	if (mapResult != segmentAddr)
	{
		printf("Failed to map ELF segment.\n");
		return 1;
	}
	if (close(fd) != 0)
	{
		printf("Failed to close file.\n");
		return 1;
	}
	
	//zerowanie końca strony
	uintptr_t restStart = phdr -> p_vaddr + phdr -> p_filesz;
	uintptr_t restStartMap = pageSizeRoundUp(restStart);
	memset((void *) (dest + restStart), 0, restStartMap - restStart);
	
	if (restStartMap < segmentEnd) {
		void *map_addr = (void *) (dest + restStartMap);
		mapResult = mmap(map_addr, segmentEnd - restStartMap,
			PROT_READ | PROT_WRITE, 
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (mapResult != map_addr) 
		{
			printf("Failed to map BSS for ELF segment\n");
			return 1;
		}
	}
	return 0;
}

void *library_getsym(struct library *lib, const char *name)
{
	int i;
	for(i = 0; i < lib -> symSize; i++) 
	{
		if(isValidSymbol(&lib -> symbols[i]) && lib -> symbols[i].st_shndx != SHN_UNDEF)
		{
			if (strcmp(name, lib -> strings + lib -> symbols[i].st_name) == 0)
				return lib -> eMap + lib -> symbols[i].st_value;
		}
	}
	return NULL;
}

//funkcja wykonująca wiązanie dla relokacji typu R_386_JMP_SLOT
void * resolveFunc(struct library * lib, int relOff)
{
	int index = relOff / sizeof (Elf32_Rel);
	const char *name = lib -> strings 
		+ lib -> symbols[ELF32_R_SYM(lib->relPlt[index].r_info)].st_name;
	Elf32_Word *dest = (Elf32_Word *)(lib -> eMap + lib -> relPlt[index].r_offset);
	void *funcAddr = lib -> getsym(name);
	*dest = (Elf32_Word) funcAddr;
	return funcAddr;
}

//funkcja zapisana pod adresem GOT o offsecie 8, zawiera assemblerowa wstawki
//których zadaniem jest przygotowanie stosu dla wywołania właściwej funkcji
void resolveLazy ()
{
	//zapamiętywanie rejestrów
	asm("pushl %eax");
	asm("pushl %ecx");
	asm("pushl %edx");
	//wrzucanie na stos parametrów dla funkcji resolveFunc
	asm("pushl 20(%esp)");
	asm("pushl 20(%esp)");
	//wywołanie funkcji resolveFunc
	asm("call resolveFunc");
	//umieszczenie w odpowiednim miejscu adresu zwrócengo przez resolveFunc
	asm("add $32, %esp");
	asm("pushl %eax");
	asm("sub $28, %esp");
	//zdjęcie ze stosu parametrów wywołania resolveFunc
	asm("add $4, %esp");
	asm("add $4, %esp");
	//przwrócenie poprzedniej wartośći reejestrom
	asm("pop %edx");
	asm("pop %ecx");
	asm("pop %eax");
	asm("pop %ebp");
	//zdjęcie uchwytu library który na stosie umieszczony był 2 razy
	asm("add $4, %esp");
	//przekazanie sterowania do wywołanej z programu, właściwej funkcji
	asm("ret");
}


//funkcja ładująca segment dynamiczny
int loadDynamic(char * buffer, Elf32_Dyn * dyn, Elf32_Word psize, 
		 struct library * lib)
{
	int i;
	char * relDynAddress;
	char * pltGot;
	int pltSize = 0;
	int relSize = 0;
	
	for (i = 0; i < psize / sizeof (Elf32_Dyn); i++)
	{
		switch (dyn[i].d_tag)
		{
			case DT_PLTRELSZ:
				pltSize = dyn[i].d_un.d_val;
				break;
			case DT_PLTGOT:
				pltGot = lib -> eMap + dyn[i].d_un.d_ptr;
				*(Elf32_Word*) (pltGot + 4) = (Elf32_Word) lib;
				*(Elf32_Word*) (pltGot + 8) = (Elf32_Word) resolveLazy;
				break;
			case DT_HASH:
				lib -> symSize = *(buffer + dyn[i].d_un.d_ptr + 4);
				break;
			case DT_STRTAB:
				lib -> strings = buffer + dyn[i].d_un.d_ptr;
				break;
			case DT_SYMTAB:
				lib -> symbols = (Elf32_Sym *) 
					(buffer + dyn[i].d_un.d_ptr);
				break;
			case DT_JMPREL:
				lib -> relPlt = (Elf32_Rel *) (buffer + dyn[i].d_un.d_ptr);
				break;
			case DT_REL:
				relDynAddress = buffer + dyn[i].d_un.d_ptr;
				break;
			case DT_RELSZ:
				relSize = dyn[i].d_un.d_val;
				break;
		}
	}
	return (relocateDyn(lib, relDynAddress, relSize) == 1 ||
		relocatePlt(lib, pltSize) == 1);
}

//funkcja wykonująca relokacje w sekcji .rel.dyn 
int relocateDyn(struct library * lib, char * addr, Elf32_Word size)
{
	int i;
	Elf32_Rel * rel = (Elf32_Rel *) addr;
	
	for (i = 0; i < size / sizeof (Elf32_Rel); i++)
	{
		int index = ELF32_R_SYM(rel[i].r_info);
		const char *symbol = lib -> strings + lib -> symbols[index].st_name;
		int type = ELF32_R_TYPE (rel[i].r_info);
		Elf32_Section shndx = lib -> symbols[index].st_shndx;
		Elf32_Addr st_value = lib -> symbols[index].st_value;
		Elf32_Word *dest = (Elf32_Word *)(lib -> eMap + rel[i].r_offset);
		
		if (!isValidSymbol( &lib -> symbols[index] ))
		{
			printf("Invalid symbol type\n");
			return 1;
		}
		
		switch (type)
		{
			case R_386_32:
				if (shndx == SHN_UNDEF)
					*dest += (Elf32_Word)lib -> getsym(symbol);
				else 
					*dest = (Elf32_Word) (lib -> eMap + st_value);
				break;

			case R_386_GLOB_DAT: 
				if (shndx == SHN_UNDEF)
					*dest = (Elf32_Word)lib -> getsym(symbol);
				else 
					*dest = (Elf32_Word) (lib -> eMap + st_value);
				break;

			case R_386_RELATIVE:
				*dest = (Elf32_Word) lib -> eMap + *dest;
				break;

			case R_386_PC32:
				if (shndx == SHN_UNDEF)
					*dest = (Elf32_Word) lib -> getsym(symbol)
						+ *dest - (Elf32_Word)dest;
				else
					*dest = (Elf32_Word) (lib -> eMap + st_value)
						+ *dest - (Elf32_Word)dest;
				break;
			default:
				printf("Invalid relocation type\n");
				return 1;
		}
	}
	return 0;
}

//funkcja wykonująca relokacje w sekcji .rel.plt
int relocatePlt(struct library * lib, Elf32_Word size)
{
	int i;
	Elf32_Rel * rel = lib -> relPlt;
	
	for (i = 0; i < size / sizeof (Elf32_Rel); i++)
	{
		int index = ELF32_R_SYM(rel[i].r_info);
	
		if (!isValidSymbol( &lib -> symbols[index] ))
		{
			printf("Invalid symbol type\n");
			return 1;
		}
		
		Elf32_Word *dest = (Elf32_Word *)(lib -> eMap + rel[i].r_offset);
		
		int type = ELF32_R_TYPE (rel[i].r_info);
		if (type == R_386_JMP_SLOT)
			*dest += (Elf32_Word) lib -> eMap;
		else
		{
			printf("Invalid relocation type\n");
			return 1;
		}
	}
	return 0;
}

