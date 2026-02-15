# Contributing Guidelines

Thank you for contributing to Nidhogg!
In order to maintain the code standard and avoid bugs please adhere to the following rules. Not following these rules will result your PR to fail.

1. Follow the code conventions of the project and use the current helper functions of the project (e.g. memory allocator, FindPattern for sig finding, etc.) , if there isn't a suitable helper function you can always add one!
2. Make sure to write (as much as possible) in C++ style and not C style code (e.g. RAII, classes, templates).
3. Make sure you are not breaking other features and test your code locally before submitting (a proper CI will also run on PR).
4. Create your PR to the dev branch.
5. If your code depends on a certain Windows version, make sure to add the right offsets to ALL supported Windows versions (Windows 10 1507 and forward) or make sure it will work only for the intended Windows version.
