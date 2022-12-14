#include "elfParser.h"
#include "except.h"

#include <fstream>

//TODO: ïðîïèñàòü args[0] è args[1]

int main(int argc, char** argv) {
	//if (argc != 3) îøèáêà
	try {
		ElfParser elf;

		std::ofstream output;
		output.open(argv[2], std::ios::out);

		if (!output)
			throw IO_Exception("File failed to open");

		elf.parse(argv[1], output);

		output.close();
	}
	catch (IO_Exception except) {
		std::cerr << except.what();
	}
	//elf.parse("test_elf", "result");
	//std::cout << __cplusplus;
}
