#include "utils.h"
#include <iostream>

long get_remaining_bits(FILE* file) {
    // Save the current position of the cursor
    long currentPos = ftell(file);

    // Go to the end of the file
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);

    // Go back to the previous position
    fseek(file, currentPos, SEEK_SET);

    // Calculate the remaining bits
    long remainingBytes = fileSize - currentPos;
    long remainingBits = remainingBytes * 8;

    return remainingBits;
}

void printBinary(uint32_t num) {
    // Start from the most significant bit
    for (int i = 31; i >= 0; --i) {
        // Check if the ith bit is set
        if (num & (1u << i))
            std::cout << "1";
        else
            std::cout << "0";

        // Print a space after every 8 bits for readability
        if (i % 8 == 0)
            std::cout << " ";
    }
    std::cout << std::endl;
}