// inject the dll parser according the binary architecture(x86/x64)

#include "peinfo.h"

BOOL alocConsole() {

	if (!AllocConsole()) {
		printf("error => AllocConsole\n");
		return FALSE;
	}
	FILE* fDummy;
	freopen_s(&fDummy, "CONIN$", "r", stdin);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
	SetConsoleTitleA("titulo");
	return TRUE;
}

DWORD WINAPI inicializa(LPVOID lpParam) {

	if (!alocConsole()) {
		printf("error => AllocConsole\n");
		return EXIT_FAILURE;
	}

	//Pointers to Struct
	PIMAGE_DOS_HEADER P_DOS_HEADER = reinterpret_cast<PIMAGE_DOS_HEADER>(GetModuleHandle(nullptr));
	//PIMAGE_NT_HEADERS32 P_NT_HEADER = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<BYTE*>(P_DOS_HEADER) + P_DOS_HEADER->e_lfanew);
	PIMAGE_NT_HEADERS64 P_NT_HEADER = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<BYTE*>(P_DOS_HEADER) + P_DOS_HEADER->e_lfanew);

	//PIMAGE_FILE_HEADER P_FILE_HEADER = &PIMAGE_NT_HEADERS32->FileHeader;
	//PIMAGE_OPTIONAL_HEADER32 P_OPTIONAL_HEADER = &P_NT_HEADER->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY P_EXPORT_DIRECTORY = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>
		(reinterpret_cast<BYTE*>(P_DOS_HEADER) + P_NT_HEADER->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR P_IMPORT_DESCRIPTOR = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>
		(reinterpret_cast<BYTE*>(P_DOS_HEADER) + P_NT_HEADER->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR P_IAT = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>
		(reinterpret_cast<BYTE*>(P_DOS_HEADER) + P_NT_HEADER->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	PIMAGE_THUNK_DATA P_THUNK = reinterpret_cast<PIMAGE_THUNK_DATA>
		(reinterpret_cast<BYTE*>(P_DOS_HEADER) + P_IMPORT_DESCRIPTOR->FirstThunk);


	std::cout << "Getting information about PE (loaded in RAM)!!\n\n";

	std::cout << "------------------\n";
	std::cout << " IMAGE_DOS_HEADER \n";
	std::cout << "------------------\n";
	std::cout << "E_magic (MZ) : \t\t\t0x" << std::hex << std::uppercase << P_DOS_HEADER->e_magic << "\n"; // Determina o formato PE
	std::cout << "E_lfanew: \t\t\t0x" << std::hex << P_DOS_HEADER->e_lfanew << "\n\n"; //Deslocamento para a struct IMAGE_NT_HEADER

	std::cout << "-----------------\n";
	std::cout << " IMAGE_NT_HEADER \n";
	std::cout << "-----------------\n";
	std::cout << "Signature: \t\t\t" << (char*)(P_NT_HEADER) << "\n"; //IMAGE_NT_HEADERS ( PE )
	std::cout << "IMAGE_NT_HEADER: \t\t0x" << std::hex << (DWORD64) P_NT_HEADER << "\n"; //Endereço para a struct IMAGE_NT_HEADER
	std::cout << "IMAGE_FILE_HEADER: \t\t0x" << (DWORD64) &P_NT_HEADER->FileHeader << "\n"; //Endereço para a struct IMAGE_FILE_HEADER
	std::cout << "IMAGE_OPTIONAL_HEADER: \t\t0x" << (DWORD64) &P_NT_HEADER->OptionalHeader << "\n\n"; //Endereço para a struct IMAGE_OPTIONAL_HEADER

	std::cout << "-------------------\n";
	std::cout << " IMAGE_FILE_HEADER \n";
	std::cout << "-------------------\n";
	std::cout << "Machine Supports:";

	if (P_NT_HEADER->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
		std::cout <<  "\t\tMachine: Intel 386 or later processor and compatible processors" << "  Offset: 0x" << P_NT_HEADER->FileHeader.Machine << "\n"; //Compatibilidade
	else
		std::cout << "\t\tMachine: Intel x64 or later processor and compatible processors" << "  Offset: 0x" << P_NT_HEADER->FileHeader.Machine << "\n";

	std::cout << "Number of Sections: \t\t" << std::dec << P_NT_HEADER->FileHeader.NumberOfSections << "\n"; //Determina o número de seções do binário

	char b[20];	{
		time_t time_date_stamp = P_NT_HEADER->FileHeader.TimeDateStamp;
		const auto time = localtime(&time_date_stamp);
		strftime(b, sizeof(b), "%D", time);
	}

	std::cout << "Date Compilation: \t\t" << b << "\n"; //Exibe a data de compilação do binário
	std::cout << "Pointer to Symbol Table: \t0x" << std::hex << P_NT_HEADER->FileHeader.PointerToSymbolTable << "\n"; //Ponteiro para a Symbol Table
	std::cout << "Number of Symbols: \t\t0x" << std::dec << P_NT_HEADER->FileHeader.NumberOfSymbols << "\n"; //Número de symbols..
	std::cout << "Size of Optional Header: \t" << std::dec << P_NT_HEADER->FileHeader.SizeOfOptionalHeader << " B\n"; //Tamanho do IMAGE_OPTIONAL_HEADER

	std::cout << "Characteristics: \t\t0x" << std::hex << std::uppercase << P_NT_HEADER->FileHeader.Characteristics << "\n\n";
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) std::cout << "  # The file does not contain base relocations\n"; //Sem info de reloc ...
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) std::cout << "  # The image file is valid and can be run\n"; //Define um executavel
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) std::cout << "  # COFF line numbers have been removed\n"; //Obsoleto e deve ser ZERO
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) std::cout << "  # COFF symbol table entries for local symbols have been removed\n"; // Obsoleto e deve ser ZERO
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) std::cout << "  # Aggressively trim working set\n"; //Obsoleto para Win 2000 e posterior e deve ser ZERO
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) std::cout << "  # Application can handle > 2 GB addresses\n"; //Aplicacao consegue trabalhar com maior que 2 GB de enderecos
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) std::cout << "  # Machine is based on a 32-bit-word architecture\n"; //32-bit arquitetura
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) std::cout << "  # Debugging information is removed from the image file\n"; //Remove info de depuracao
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) std::cout << "  # If the image is on removable media, fully load it and copy it to the swap file\n"; //Se estiver em midia removivel carregue e copie para arquivo de troca
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) std::cout << "  # If the image is on network media, fully load it and copy it to the swap file\n"; //Se estiver na rede carregue e copie para arquivo de troca
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) std::cout << "  # The image file is a system file, not a user program\n"; //Arquivo de imagem pertence ao sistema e nao ao user
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_DLL) std::cout << "  # The image file is a dynamic-link library (DLL)\n"; //Considerado um arquivo executavel porem nao diretamente
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) std::cout << "  # The file should be run only on a uniprocessor machine\n"; //Arquivo so pode ser executado em um unico processador
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_LO) std::cout << "  # Little endian\n"; //Obsoleto e deve ser ZERO
	if (P_NT_HEADER->FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_HI) std::cout << "  # Big endian\n"; //Obsoleto e deve ser ZERO

	std::cout << "\n-----------------------";
	std::cout << "\n IMAGE_OPTIONAL_HEADER ";
	std::cout << "\n-----------------------\n";
	std::cout << "Magic: \t\t\t\t0x" << std::hex << P_NT_HEADER->OptionalHeader.Magic << "\n"; //Identificaçao do tipo de IMAGEM
	std::cout << "MajorLinkVersion: \t\t" << reinterpret_cast<int*>(P_NT_HEADER->OptionalHeader.MajorLinkerVersion) << "\n"; //Maior versao do link
	std::cout << "MinorLinkVersion: \t\t" << reinterpret_cast<int*>(P_NT_HEADER->OptionalHeader.MinorLinkerVersion) << "\n"; //Menor versao do link
	std::cout << "SizeOfCode: \t\t\t" << std::dec << P_NT_HEADER->OptionalHeader.SizeOfCode << " B\n"; //Tamanho da secao CODE ( Normalmente .text nas aplicacoes por ai )
	std::cout << "SizeOfInitializedData: \t\t" << std::dec << P_NT_HEADER->OptionalHeader.SizeOfInitializedData << " B\n"; //Tamanho da secao DATA ( Normalmente .data nas aplicacoes por ai )
	std::cout << "SizeOfUnitializedData: \t\t" << std::dec << P_NT_HEADER->OptionalHeader.SizeOfUninitializedData << " B\n";
	std::cout << "AddressOfEntryPoint: \t\t0x" << std::hex << P_NT_HEADER->OptionalHeader.AddressOfEntryPoint << "\n"; //RVA do entry point no caso em relacao ao ImageBase ( 0x400000 )
	std::cout << "BaseOfCode: \t\t\t0x" << P_NT_HEADER->OptionalHeader.BaseOfCode << "\n"; //RVA do comeco da secao code ( .text )
	//std::cout << "BaseOfData: 0x" << P_IMAGE_OPTIONAL_HEADER->BaseOfData << "\n"; //O nome da diz e a mesma coisa acima porem o RVA e para a secao de dados ( .data )
	std::cout << "ImageBase: \t\t\t0x" << P_NT_HEADER->OptionalHeader.ImageBase << "\n"; //ImageBase do binario, no caso quando uma aplicacao e executada ela recebe um valor inicial de memoria ( 0x400000 )
	std::cout << "SectionAlignment: \t\t0x" << P_NT_HEADER->OptionalHeader.SectionAlignment << "\n"; //Alinhamento das secoes em bytes
	std::cout << "FileAlignment: \t\t\t0x" << P_NT_HEADER->OptionalHeader.FileAlignment << "\n"; //Alinhamento das secoes de dados e caso o SectionAlignment seja menor que o size de uma pagina ela vai possuir o mesmo tamanho da FileAlignment
	std::cout << "MajorImageVersion: \t\t" << P_NT_HEADER->OptionalHeader.MajorImageVersion << "\n"; //Indicam o maior tamanho da image
	std::cout << "MinorImageVersion: \t\t" << P_NT_HEADER->OptionalHeader.MinorImageVersion << "\n"; //Indicam o menor tamanho da image ( No caso sao 2 WORDS )
	std::cout << "MajorSubsystemVersion: \t\t" << P_NT_HEADER->OptionalHeader.MajorSubsystemVersion << "\n"; //Indica o maior tamanho da subsystem
	std::cout << "MinorSubsystemVersion: \t\t" << P_NT_HEADER->OptionalHeader.MinorSubsystemVersion << "\n"; //Indica o menor tamanho da Subsystem e isso vai influenciar como uma aplicacao roda ( questao grafica por ex... )
	std::cout << "Win32VersionValue: \t\t" << P_NT_HEADER->OptionalHeader.Win32VersionValue << "\n"; //A principio e sempre ZERO
	std::cout << "SizeOfImage: \t\t\t" << std::dec << P_NT_HEADER->OptionalHeader.SizeOfImage << " B\n"; //Tamanho total da Image quando carregada na memoria
	std::cout << "SizeOfHeader: \t\t\t" << std::dec << P_NT_HEADER->OptionalHeader.SizeOfHeaders << " B\n"; //Tamanho de todos cabecalhos data, code, etc..
	std::cout << "CheckSum: \t\t\t0x" << std::hex << P_NT_HEADER->OptionalHeader.CheckSum << "\n"; //So e checada se a image for um Driver NT

	std::cout << "Subsystem: \t\t\t" << std::dec << P_NT_HEADER->OptionalHeader.Subsystem << std::hex << "\n\n"; //Espera o subsystem adequado para executar a imagem
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_UNKNOWN) std::cout << "  # An unknown subsystem\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_NATIVE) std::cout << "  # Device drivers and native Windows processe\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_WINDOWS_GUI) std::cout << "  # The Windows graphical user interface (GUI) subsystem\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_WINDOWS_CUI) std::cout << "  # The Windows character subsystem\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_OS2_CUI) std::cout << "  # The OS/2 character subsystem\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_POSIX_CUI)	std::cout << "  # The Posix character subsystem\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_NATIVE_WINDOWS) std::cout << "  # Native Win9x driver\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_WINDOWS_CE_GUI) std::cout << "  # Windows CE\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_EFI_APPLICATION) std::cout << "  # An Extensible Firmware Interface (EFI) application\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) std::cout << "  # An EFI driver with boot services\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) std::cout << "  # An EFI driver with run-time services\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_EFI_ROM) std::cout << "  # An EFI ROM image\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_XBOX) std::cout << "  # XBOX\n";
	if (P_NT_HEADER->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION) std::cout << "  # Windows boot application\n";

	std::cout << "\nDllCharacteristics: \t\t" << P_NT_HEADER->OptionalHeader.DllCharacteristics << "\n\n"; //Como nao e uma dll e sim um .exe o campo estara ZERADO
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) std::cout << "  # Image can handle a high entropy 64-bit virtual address space\n";
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) std::cout << "  # DLL can move\n";
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) std::cout << "  # Code Integrity Image\n";
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) std::cout << "  # Image is NX compatible\n";
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) std::cout << "  # Image understands isolation and doesn't want it\n";
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) std::cout << "  # Image does not use SEH.  No SE handler may reside in this image\n";
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) std::cout << "  # Do not bind this image\n";
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) std::cout << "  # Image should execute in an AppContainer\n";
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) std::cout << "  # Driver uses WDM model\n";
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) std::cout << "  # Image supports Control Flow Guard\n";
	if (P_NT_HEADER->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) std::cout << "  # Indicate that your application is Remote Desktop Services aware\n";

	std::cout << "SizeOfStackReserved: \t\t" << std::dec << P_NT_HEADER->OptionalHeader.SizeOfStackReserve << " B\n"; //Espaco que sera reservado para a stack ( pilha )
	std::cout << "SizeOfStackCommit: \t\t" << std::dec << P_NT_HEADER->OptionalHeader.SizeOfStackCommit << " B\n"; //Espaco que sera entregue a ela
	std::cout << "SizeOfHeapReserved: \t\t" << std::dec << P_NT_HEADER->OptionalHeader.SizeOfHeapReserve << " B\n"; //Espaco que sera entregue a ela
	std::cout << "SizeOfHeapCommit: \t\t" << std::dec << P_NT_HEADER->OptionalHeader.SizeOfHeapCommit << " B\n"; //Espaco que sera entregue a ela
	std::cout << "LoaderFlags: \t\t\t0x" << std::hex << P_NT_HEADER->OptionalHeader.LoaderFlags << "\n"; //Reservado e ZERADA
	std::cout << "NumberOfRVAandSizes: \t\t" << std::dec << P_NT_HEADER->OptionalHeader.NumberOfRvaAndSizes << " B\n\n\n"; //Numero de entradadas do DataDirectory


	system("pause");
	return 0;
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        	CreateThread(0, 0, &inicializa, 0, 0, 0);
            // attach to process
            // return FALSE to fail DLL load
            break;

        case DLL_PROCESS_DETACH:
            // detach from process
            break;

        case DLL_THREAD_ATTACH:
            // attach to thread
            break;

        case DLL_THREAD_DETACH:
            // detach from thread
            break;
    }
    return TRUE; // succesful
}
