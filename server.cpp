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

#include "utils.h"

/**
 * Check if two encrypted numbers are equal
 */
void check_equal_encrypted(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    // Comparaison bit par bit
    for (int i = 0; i < nb_bits; ++i) {
        bootsXNOR(&result[i], &a[i], &b[i], bk);
    }
    // AND tous les résultats de XOR pour obtenir un bit unique
    for (int i = 1; i < nb_bits; ++i) {
        bootsAND(&result[0], &result[0], &result[i], bk);
    }
}

int main(){

    FILE* cloud_key = fopen(NAME_FILE_PUBLIC_KEY.c_str(), "rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    const TFheGateBootstrappingParameterSet* params = bk->params;

    // Read banned IPs

    FILE* banned_ip_data = fopen(NAME_FILE_WITH_CIPHER_BANNED_IPS.c_str(), "rb");

    std::vector<LweSample *> ipBannedCypher;
    while(true){
        if(get_remaining_bits(banned_ip_data) == 0) break;
        LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(32, params);
        for (int j=0; j<32; j++) import_gate_bootstrapping_ciphertext_fromFile(banned_ip_data, &ciphertext[j], params);
        ipBannedCypher.push_back(ciphertext);

    }

    // Read network flow

    FILE* cloud_data = fopen(NAME_FILE_WITH_CIPHER_NETWORK_FLOW.c_str(),"rb");
    FILE* answer_data = fopen(NAME_FILE_WITH_RESULT_OF_ANALYZE.c_str(),"wb");

    while(true){
        if(get_remaining_bits(cloud_data) == 0) break;
        LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(32, params);
        for (int l=0; l<32; l++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext[l], params);
        
        for(int j = 0 ; j < ipBannedCypher.size() ; j++){
            LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
            check_equal_encrypted(result, ciphertext, ipBannedCypher[j], 32, bk);
            export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[0], params);
            for(int z = 0 ; z < 32 ; z++) export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertext[z], params);

            delete_gate_bootstrapping_ciphertext_array(32, result);
        }

        delete_gate_bootstrapping_ciphertext_array(32, ciphertext);

    }
    fclose(answer_data);
    fclose(cloud_data);

    // Clean up all pointers
    for(int j = 0 ; j < ipBannedCypher.size() ; j++){
        delete_gate_bootstrapping_ciphertext_array(32, ipBannedCypher[j]);
    }

    delete_gate_bootstrapping_cloud_keyset(bk);
}