#include "pch.h"
#include "NidhoggInterface.h"

int main(int argc, char* argv[]) {
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
