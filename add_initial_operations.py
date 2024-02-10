import os


def main():
    operations_size = 0
    initial_operations = ''
    current_path = os.path.dirname(os.path.realpath(__file__))

    # If the initial operations file exists, read it.
    if os.path.exists(os.path.join(current_path, "out.ndhg")):
        with open(os.path.join(current_path, "out.ndhg"), "rb") as initial_opearations_file:
            data = initial_opearations_file.read()
            operations_size = len(data)
            hexed_data = [hex(b) for b in data]
            initial_operations = ",".join(hexed_data)

    # Creating the new header file.
    new_initial_operations = '#pragma once\n#include \"pch.h\"\n\n'

    if operations_size == 0:
        new_initial_operations += 'constexpr SIZE_T InitialOperationsSize = 0;\n'
        new_initial_operations += 'constexpr UCHAR InitialOperations = {};\n'
    else:
        new_initial_operations += f'constexpr SIZE_T InitialOperationsSize = {operations_size};\n'
        new_initial_operations += 'constexpr UCHAR InitialOperations[InitialOperationsSize] = {' + initial_operations + '};\n'

    # Writing the new header file.
    with open(os.path.join(current_path, "Nidhogg\\InitialOperation.hpp"), "w") as initial_opeartions_header:
        initial_opeartions_header.write(new_initial_operations)


if __name__ == "__main__":
    main()
