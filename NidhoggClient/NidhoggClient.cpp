#include "pch.h"
#include "NidhoggClient.h"

int main(int argc, char* argv[]) {
	if (!EnableColors())
		std::cerr << "Failed to enable colors in console :(" << std::endl;
	PrintAsciiArt();

	try {
		NidhoggInterface nidhoggInterface = NidhoggInterface();

		switch (argc) {
			case 1:
				nidhoggInterface.HandleCommands();
				break;
			case 3:
				nidhoggInterface.HandleCommand(argv[1], argv[2]);
				break;
			default:
				std::cerr << termcolor::underline << termcolor::red << "Invalid number of arguments!" << termcolor::reset << std::endl;
				std::cerr << "\t" << argv[0] << std::endl;
				std::cerr << "\t" << argv[0] <<" <command> <argument>" << std::endl;
				return ERROR_INVALID_PARAMETER;
		}
	}
	catch (const NidhoggInterfaceException& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return ERROR_BAD_ENVIRONMENT;
	}
	return ERROR_SUCCESS;
}
