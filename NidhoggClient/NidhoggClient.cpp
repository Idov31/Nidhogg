#include "pch.h"
#include "NidhoggClient.h"

int main(int argc, char* argv[]) {
	if (!EnableColors())
		std::cerr << "Failed to enable colors in console :(" << std::endl;
	PrintAsciiArt();

	try {
		NidhoggInterface nidhoggInterface = NidhoggInterface();
		nidhoggInterface.HandleCommands();
	}
	catch (const NidhoggInterfaceException& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return ERROR_BAD_ENVIRONMENT;
	}
	return ERROR_SUCCESS;
}
