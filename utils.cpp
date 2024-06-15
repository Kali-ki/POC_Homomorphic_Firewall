#include "utils.h"
#include <iostream>

long get_remaining_bits(FILE* file) {
    // Enregistrer la position actuelle du curseur de lecture
    long currentPos = ftell(file);

    // Aller à la fin du fichier pour obtenir sa taille
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);

    // Remettre le curseur de lecture à sa position initiale
    fseek(file, currentPos, SEEK_SET);

    // Calculer le nombre de bits restants à lire
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