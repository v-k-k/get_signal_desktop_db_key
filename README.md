# Simple program to retrieve your own Signal Desktop decrypted DB key

Once the basic requirements are installed, no additional setup is needed to run the Python script.

## To compile the C++ file on Windows, install MSYS2 and the required dependencies:

*pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl*
*pacman -S --needed mingw-w64-ucrt-x86_64-toolchain*

## To compile with static linking for a portable .exe that has no DLL dependencies:

*g++ get_db_key.cpp -o get_db_key.exe   $(pkg-config --cflags --libs openssl)   -lcrypt32 -lws2_32 -static -std=c++17*
