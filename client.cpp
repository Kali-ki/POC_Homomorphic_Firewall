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

const int MINIMUM_LAMBDA = 110;
const std::string NAME_FILE_PRIVATE_KEY = "secret.key";
const std::string NAME_FILE_WITH_BANNED_IPS = "banned_ip.txt";
const std::string NAME_FILE_WITH_NETWORK_FLOW = "networkflow.txt";

// === UTILS FUNCTIONS ============================================================================

/**
 * Read IP addresses from a file
 */
std::vector<std::string> readIPAddressesFromFile(const std::string& filename) {
    std::vector<std::string> ipAddresses;
    std::ifstream inputFile(filename);
    
    if (!inputFile.is_open()) {
        std::cerr << "Erreur: Impossible d'ouvrir le fichier " << filename << std::endl;
        return ipAddresses;
    }
    
    std::string line;
    while (std::getline(inputFile, line)) {
        ipAddresses.push_back(line);
    }
    
    inputFile.close();
    return ipAddresses;
}

/**
 * Convert an IPv4 address from string to uint32_t
 */
uint32_t convert( const std::string& ipv4Str )
{
    std::istringstream iss( ipv4Str );
    
    uint32_t ipv4 = 0;
    
    for( uint32_t i = 0; i < 4; ++i ) {
        uint32_t part;
        iss >> part;
        if ( iss.fail() || part > 255 ) {
            throw std::runtime_error( "Invalid IP address - Expected [0, 255]" );
        }
        
        // LSHIFT and OR all parts together with the first part as the MSB
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
 */
std::string convert( uint32_t ipv4 )
{
    std::ostringstream oss;
    
    for( uint32_t i = 0; i < 4; ++i ) {
        oss << ( ( ipv4 >> ( 8 * ( 3 - i ) ) ) & 0xFF );
        
        // Append delimiter except on last iteration
        if ( i != 3 ) {
            oss << '.';
        }
    }
    
    return oss.str();
}

/**
 * Encrypt an 32 bits type
 */
LweSample* cipher_int(int plaintext, TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingParameterSet* params) {
    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(32, params);
    for (int i = 0; i < 32; i++) {
        bootsSymEncrypt(&ciphertext[i], (plaintext >> i) & 1, key);
    }
    return ciphertext;
}

/**
 * Decrypt an 32 bits type
 */
int decrypt_int(LweSample* ciphertext, TFheGateBootstrappingSecretKeySet* key) {
    int decrypted = 0;
    for (int i = 0; i < 32; i++) {
        int ai = bootsSymDecrypt(&ciphertext[i], key);
        decrypted |= (ai << i);
    }
    return decrypted;
}

/**
 * Extract unique IPs from a file
 */
std::set<std::string> extractUniqueIPsFromFile(const std::string& filename) {
    std::ifstream file(filename);

    std::set<std::string> uniqueIPs;

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string token;
        while (iss >> token) {
            if (token.find('.') != std::string::npos) { // Vérifier si le token contient un point (supposition : c'est une adresse IP)
                uniqueIPs.insert(token);
            }
        }
    }

    file.close();

    return uniqueIPs;
}

/**
 * Cipher IP addresses in a file
 */
void cipher_ips_in_file(const std::string& filename, std::vector<std::string> IPAdresses, TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingParameterSet* params){

    // Create vector with cipher ip object
    std::vector<LweSample *> crypted_ips;
    int number_of_ip = IPAdresses.size();
    for(int i = 0 ; i < number_of_ip ; i++){
        uint32_t ip = convert(IPAdresses[i]);
        LweSample* cipher_ip = cipher_int(ip, key, params);
        crypted_ips.push_back(cipher_ip);
    }

    FILE* banned_ip_data = fopen(filename.c_str(),"wb");
    // Write all ips
    for(int j = 0 ; j < number_of_ip ; j++){
        for(int i = 0 ; i < 32 ; i++){
            export_gate_bootstrapping_ciphertext_toFile(banned_ip_data, &crypted_ips[j][i], params);
        }
    }
    fclose(banned_ip_data);

}

// === 3 MAINS FUNCTION ===========================================================================

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

    // Appel de la fonction pour lire les adresses IP
    std::vector<std::string> ipAddresses = readIPAddressesFromFile(NAME_FILE_WITH_BANNED_IPS);

    // Chiffre IP dans un banned_ip.data
    cipher_ips_in_file(NAME_FILE_WITH_CIPHER_BANNED_IPS, ipAddresses, key, params);

    // Clean up all pointers
    TFheGateBootstrappingParameterSet * paramsCopy = (TFheGateBootstrappingParameterSet *)params;
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(paramsCopy);
}

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
   
    // Chiffre IP dans un banned_ip.data
    cipher_ips_in_file(NAME_FILE_WITH_CIPHER_NETWORK_FLOW, ipVector, key, params);

    // Clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
}

void result(){

    //reads the cloud key from file
    FILE* secret_key = fopen(NAME_FILE_PRIVATE_KEY.c_str(),"rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    FILE* answer_data = fopen(NAME_FILE_WITH_RESULT_OF_ANALYZE.c_str(),"rb");
    int f = 0;
    while(true){

        if(get_remaining_bits(answer_data) == 0) break;

        //read the 16 ciphertexts of the result
        LweSample* answer = new_gate_bootstrapping_ciphertext_array(1, params);
        LweSample* ip = new_gate_bootstrapping_ciphertext_array(32, params);

        //import the 32 ciphertexts from the answer file
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &answer[0], params);
        for(int j = 0 ; j < 32 ; j++){
            import_gate_bootstrapping_ciphertext_fromFile(answer_data, &ip[j], params);
        }

        int int_answer = bootsSymDecrypt(&answer[0], key);

        if(int_answer == 1){
            f++;
            uint32_t decrypted_ip = decrypt_int(ip, key);
            std::cout << "IP: " << convert(decrypted_ip) << " is banned" << std::endl;
        }

        delete_gate_bootstrapping_ciphertext_array(1, answer);
        delete_gate_bootstrapping_ciphertext_array(32, ip);
    }

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