#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <cstdint>
#include <set>
#include <cstdio>

#include "utils.h"

// === CONSTANTS ==================================================================================

// Constants of the client
const int MINIMUM_LAMBDA = 110;
const std::string NAME_FILE_PRIVATE_KEY = "secret.key";
const std::string NAME_FILE_WITH_BANNED_IPS = "banned_ip.txt";
const std::string NAME_FILE_WITH_NETWORK_FLOW = "networkflow.txt";

// === UTILS FUNCTIONS ============================================================================

/**
 * Read IP addresses from a file
 * @param filename The name of the file to read
 * @return A vector containing the IP addresses
 */
std::vector<std::string> readIPAddressesFromFile(const std::string& filename) {
    std::vector<std::string> ipAddresses;
    std::ifstream inputFile(filename);
    
    // Check if the file is open
    if (!inputFile.is_open()) {
        std::cerr << "Erreur: Impossible d'ouvrir le fichier " << filename << std::endl;
        return ipAddresses;
    }
    
    // Read the file line by line, and add each line to the vector
    std::string line;
    while (std::getline(inputFile, line)) {
        ipAddresses.push_back(line);
    }
    
    inputFile.close();
    return ipAddresses;
}

/**
 * Convert an IPv4 address from string to uint32_t
 * Each octet of the IP address are converted to a 8-bit integer
 * The 4 octets are then concatenated to form a 32-bit integer
 * @param ipv4Str The IPv4 address in string format
 * @return The IPv4 address in uint32_t format
 */
uint32_t convert( const std::string& ipv4Str )
{   
    // Split the string into parts
    std::istringstream iss( ipv4Str );
    
    uint32_t ipv4 = 0;
    
    // Parse each octet
    for( uint32_t i = 0; i < 4; ++i ) {
        uint32_t part;

        // Read the part and check for errors
        iss >> part;
        if ( iss.fail() || part > 255 ) {
            throw std::runtime_error( "Invalid IP address - Expected [0, 255]" );
        }
        
        // Add the part to the IPv4 address
        ipv4 |= part << ( 8 * ( 3 - i ) );

        // Check for delimiter except on last iteration
        if ( i != 3 ) {
            char delimiter;
            iss >> delimiter;
            if ( iss.fail() || delimiter != '.' ) {
                throw std::runtime_error( "Invalid IP address - Expected '.' delimiter" );
            }
        }
    }
    
    return ipv4;
}

/**
 * Convert an IPv4 address from uint32_t to string
 * This is the reverse operation of the convert function above
 * @param ipv4 The IPv4 address in uint32_t format
 * @return The IPv4 address in string format
 */
std::string convert( uint32_t ipv4 )
{
    std::ostringstream oss;
    
    // Extract each octet from the 32-bit integer
    for( uint32_t i = 0; i < 4; ++i ) {
        oss << ( ( ipv4 >> ( 8 * ( 3 - i ) ) ) & 0xFF );
        
        // Append delimiter except on last iteration
        if ( i != 3 ) {
            oss << '.';
        }
    }
    
    // Return the string representation of the IPv4 address
    return oss.str();
}

/**
 * Encrypt an 32 bits type
 * @param value The value to encrypt
 * @param key The secret key
 * @param params The parameters
 * @return The encrypted value
 */
LweSample* cipher_int(int value, TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingParameterSet* params) {
    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(32, params);
    // Encrypt the 32 bits
    for (int i = 0; i < 32; i++) {
        // Encrypt one bit
        bootsSymEncrypt(&ciphertext[i], (value >> i) & 1, key);
    }
    return ciphertext;
}

/**
 * Decrypt an 32 bits type
 * @param cipher_value The value to decrypt
 * @param key The secret key
 * @return The decrypted value
 */
int decrypt_int(LweSample* cipher_value, TFheGateBootstrappingSecretKeySet* key) {
    int decrypted = 0;
    // Decrypt the 32 bits
    for (int i = 0; i < 32; i++) {
        // Decrypt one bit
        int ai = bootsSymDecrypt(&cipher_value[i], key);
        // Add the bit to the decrypted value
        decrypted |= (ai << i);
    }
    return decrypted;
}

/**
 * Extract unique IPs from a file
 * @param filename The name of the file to read
 * @return A set containing the unique IP addresses
 */
std::set<std::string> extractUniqueIPsFromFile(const std::string& filename) {
    std::ifstream file(filename);
    
    std::set<std::string> uniqueIPs;

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string token;
        // Split the line into tokens
        while (iss >> token) {
            // Check if the token is an IP address
            if (token.find('.') != std::string::npos) {
                // Add the IP address to the set
                uniqueIPs.insert(token);
            }
        }
    }

    file.close();

    return uniqueIPs;
}

/**
 * Cipher IP addresses in a file
 * @param filename The name of the file to write
 * @param IPAdresses The IP addresses to cipher
 * @param key The secret key
 * @param params The parameters
 */
void cipher_ips_in_file(const std::string& filename, std::vector<std::string> IPAdresses, TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingParameterSet* params){

    // Create vector with crypted IP addresses objects
    std::vector<LweSample *> crypted_ips;
    int number_of_ip = IPAdresses.size();
    for(int i = 0 ; i < number_of_ip ; i++){
        uint32_t ip = convert(IPAdresses[i]);
        LweSample* cipher_ip = cipher_int(ip, key, params);
        crypted_ips.push_back(cipher_ip);
    }

    FILE* banned_ip_data = fopen(filename.c_str(),"wb");
    // Write all IP addresses to the file
    for(int j = 0 ; j < number_of_ip ; j++){
        for(int i = 0 ; i < 32 ; i++){
            export_gate_bootstrapping_ciphertext_toFile(banned_ip_data, &crypted_ips[j][i], params);
        }
    }
    fclose(banned_ip_data);

}

// === 3 MAINS FUNCTION ===========================================================================

/**
 * Initialize the system
 * Generate a keyset, export the private and public keys
 * Read the banned IP addresses from a file
 * Encrypt the IP addresses and write them to a file
 */
void initialize(){

    // Generate a keyset
    const TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(MINIMUM_LAMBDA);
    // Create a random seed
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    // Generate a random key thanks to the seed and the parameters
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    // Export Private key
    FILE* secret_key = fopen(NAME_FILE_PRIVATE_KEY.c_str(),"wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    // Export Public key
    FILE* cloud_key = fopen(NAME_FILE_PUBLIC_KEY.c_str(),"wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    // Call the function to read the IP addresses from the file
    std::vector<std::string> ipAddresses = readIPAddressesFromFile(NAME_FILE_WITH_BANNED_IPS);

    // Encrypt the IP addresses and write them to a file
    cipher_ips_in_file(NAME_FILE_WITH_CIPHER_BANNED_IPS, ipAddresses, key, params);

    // Clean up all pointers
    TFheGateBootstrappingParameterSet * paramsCopy = (TFheGateBootstrappingParameterSet *)params;
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(paramsCopy);
}

/**
 * Analyze the network flow
 * Read the cloud key from a file
 * Extract all IP addresses from the network flow
 * Encrypt the IP addresses and write them to a file
 */
void analyze(){

    //reads the cloud key from file
    FILE* secret_key = fopen(NAME_FILE_PRIVATE_KEY.c_str(),"rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    const TFheGateBootstrappingParameterSet* params = key->params;

    // Extract all IPS from network.txt
    std::set<std::string> uniqueIPs = extractUniqueIPsFromFile(NAME_FILE_WITH_NETWORK_FLOW);

    // Convert set to vector
    std::vector<std::string> ipVector(uniqueIPs.begin(), uniqueIPs.end());
   
    // Encrypt the IP addresses and write them to a file
    cipher_ips_in_file(NAME_FILE_WITH_CIPHER_NETWORK_FLOW, ipVector, key, params);

    // Clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
}

/**
 * Get the result of the analysis
 * Read the secret key from a file
 * Read the result of the analysis from a file
 * Decrypt the result and print the banned IP addresses
 */
void result(){

    //reads the secret key from file
    FILE* secret_key = fopen(NAME_FILE_PRIVATE_KEY.c_str(),"rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    const TFheGateBootstrappingParameterSet* params = key->params;

    FILE* answer_data = fopen(NAME_FILE_WITH_RESULT_OF_ANALYZE.c_str(), "rb");
    int f = 0;
    while(true){
        
        // Check if there are remaining bits to read in the file
        if(get_remaining_bits(answer_data) == 0) break;

        // Create two objects to store the answer and the IP
        LweSample* answer = new_gate_bootstrapping_ciphertext_array(1, params);
        LweSample* ip = new_gate_bootstrapping_ciphertext_array(32, params);

        // Read 1 bit from the file, this is the answer of the analysis (1 if the IP is banned, 0 otherwise)
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &answer[0], params);
        // Read 32 bits from the file, this is the IP address
        for(int j = 0 ; j < 32 ; j++){
            import_gate_bootstrapping_ciphertext_fromFile(answer_data, &ip[j], params);
        }

        // Decrypt the answer
        int int_answer = bootsSymDecrypt(&answer[0], key);

        // If the answer is 1, decrypt the IP and print it
        if(int_answer == 1){
            f++;
            uint32_t decrypted_ip = decrypt_int(ip, key);
            std::cout << "IP: " << convert(decrypted_ip) << " is banned" << std::endl;
        }

        delete_gate_bootstrapping_ciphertext_array(1, answer);
        delete_gate_bootstrapping_ciphertext_array(32, ip);
    }

    // Print the result
    std::cout << std::endl;
    if(f == 0){
        std::cout << "No banned IP => Network flow is safe" << std::endl;
    }else{
        std::cout << "Number of banned IP : " << f << " => Network flow is not safe" << std::endl;
    }

    fclose(answer_data);

    //clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
}

// === THE MAIN FUNCTION ==========================================================================

int main (int argc, char *argv[]) {

    // Check the number of arguments, if it's not 2 or 3, print an error message
    if(argc < 2 || argc > 3){
        std::cerr << "Commande usage : client [initialize|analyze|result]";
        return 1;
    }

    std::string argv1(argv[1]);

    if(argv1.compare("initialize") == 0){
        initialize();
    }else if(argv1.compare("analyze") == 0){
        analyze();
    }else if(argv1.compare("result") == 0){
        result();
    }else{
        std::cerr << "Commande usage : client [initialize|analyze|result]";
        return 1;
    }

}