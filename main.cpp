#include <stdio.h>
#include <string.h>
#include <mbedtls/aes.h>  // Use mbedTLS instead of esp_aes.h

// Hardcoded inputs (full 162 bytes, uppercase hex)
const uint8_t telegram[162] = {
    0xA1, 0x44, 0xC5, 0x14, 0x27, 0x85, 0x89, 0x50, 0x70, 0x07, 0x8C, 0x20, 0x60, 0x7A,
    0x9D, 0x00, 0x90, 0x25, 0x37, 0xCA, 0x23, 0x1F, 0xA2, 0xDA, 0x58, 0x89, 0xBE, 0x8D,
    0xF3, 0x67, 0x3E, 0xC1, 0x36, 0xAE, 0xBF, 0xB8, 0x0D, 0x4C, 0xE3, 0x95, 0xBA, 0x98,
    0xF6, 0xB3, 0x84, 0x4A, 0x11, 0x5E, 0x4B, 0xE1, 0xB1, 0xC9, 0xF0, 0xA2, 0xD5, 0xFF,
    0xBB, 0x92, 0x90, 0x6A, 0xA3, 0x88, 0xDE, 0xAA, 0x82, 0xC9, 0x29, 0x31, 0x0E, 0x9E,
    0x5C, 0x4C, 0x09, 0x22, 0xA7, 0x84, 0xDF, 0x89, 0xCF, 0x0D, 0xED, 0x83, 0x3B, 0xE8,
    0xDA, 0x99, 0x6E, 0xB5, 0x88, 0x54, 0x09, 0xB6, 0xC9, 0x86, 0x79, 0x78, 0xDE, 0xA2,
    0x40, 0x01, 0xD6, 0x8C, 0x60, 0x34, 0x08, 0xD7, 0x58, 0xA1, 0xE2, 0xB9, 0x1C, 0x42,
    0xEB, 0xAD, 0x86, 0xA9, 0xB9, 0xD2, 0x87, 0x88, 0x00, 0x83, 0xBB, 0x07, 0x02, 0x85,
    0x05, 0x74, 0xD7, 0xB5, 0x1E, 0x9C, 0x20, 0x9E, 0xD6, 0x8E, 0x03, 0x74, 0xE9, 0xB0,
    0x1F, 0xEB, 0xFD, 0x92, 0xB4, 0xCB, 0x94, 0x10, 0xFD, 0xEA, 0xF7, 0xFB, 0x52, 0x6B,
    0x74, 0x2D, 0xC9, 0xA8, 0xD0, 0x68, 0x26, 0x53
};

const uint8_t key[16] = {0x42, 0x55, 0x79, 0x4D, 0x3D, 0xCC, 0xFD, 0x46, 0x95, 0x31, 0x46, 0xE7, 0x01, 0xB7, 0xDB, 0x68};

void decrypt_wmbus_telegram() {
    // Step 1: Parse DLL header
    if (telegram[0] != 0xA1 || telegram[1] != 0x44) {
        printf("Error: Invalid L or C field\n");
        return;
    }
    uint8_t M[2] = {telegram[2], telegram[3]};
    uint8_t ID[4] = {telegram[4], telegram[5], telegram[6], telegram[7]};
    uint8_t V = telegram[8];
    uint8_t D = telegram[9];

    printf("Parsed DLL Header:\n");
    printf("Manufacturer: 0x%02X %02X\n", M[0], M[1]);
    printf("ID (Serial): 0x");
    for (int i = 0; i < 4; i++) { printf("%02X", ID[i]); }
    printf("\nVersion: 0x%02X\n", V);
    printf("Device Type: 0x%02X\n", D);

    // Step 2: Check for ELL
    int pos = 10;
    uint8_t ell_ci = telegram[pos];
    uint8_t ell_cc = 0, ell_acc = 0;
    int ell_len = 0;
    if (ell_ci == 0x8C) {
        ell_len = 2;
        ell_cc = telegram[pos + 1];
        ell_acc = telegram[pos + 2];
        pos += 3;
        printf("ELL Present:\n");
        printf("ELL-CC: 0x%02X\n", ell_cc);
        printf("ELL-ACC/SN: 0x%02X\n", ell_acc);
    } else {
        printf("No ELL.\n");
    }

    // Step 3: Parse TPL
    uint8_t tpl_ci = telegram[pos];
    if (tpl_ci != 0x7A) {
        printf("Error: Unexpected TPL-CI (expected 0x7A)\n");
        return;
    }
    pos++;
    uint8_t tpl_acc = telegram[pos++];
    uint8_t tpl_sts = telegram[pos++];
    uint8_t cfg_l = telegram[pos++];
    uint8_t cfg_h = telegram[pos++];
    uint16_t cfg = (cfg_h << 8) | cfg_l;

    printf("Parsed TPL Header:\n");
    printf("TPL-ACC: 0x%02X\n", tpl_acc);
    printf("TPL-STS: 0x%02X\n", tpl_sts);
    printf("Config Field: 0x%04X\n", cfg);

    // Step 4: Determine N
    int N = (cfg_l >> 4) & 0x0F;
    int enc_len = N * 16;
    if (enc_len == 0 || pos + enc_len > sizeof(telegram)) {
        printf("Error: Invalid encrypted length\n");
        return;
    }
    printf("Encrypted blocks (N): %d (length: %d bytes)\n", N, enc_len);

    // Step 5: Build IV
    uint8_t iv[16] = {M[0], M[1], ID[0], ID[1], ID[2], ID[3], V, D, tpl_acc, tpl_acc, tpl_acc, tpl_acc, tpl_acc, tpl_acc, tpl_acc, tpl_acc};

    printf("IV: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", iv[i]);
    }
    printf("\n");

    // Step 6: Extract encrypted data
    uint8_t enc_data[enc_len];
    memcpy(enc_data, &telegram[pos], enc_len);

    // Step 7: Decrypt using mbedTLS AES-128-CBC
    uint8_t dec_data[enc_len];
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_dec(&ctx, key, 128) != 0) {
        printf("Error: AES setkey failed\n");
        return;
    }
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, enc_len, iv_copy, enc_data, dec_data) != 0) {
        printf("Error: AES decryption failed\n");
        mbedtls_aes_free(&ctx);
        return;
    }
    mbedtls_aes_free(&ctx);

    // Step 8: Verify leading 0x2F 0x2F
    if (dec_data[0] != 0x2F || dec_data[1] != 0x2F) {
        printf("Error: Invalid decryption (missing leading 0x2F 0x2F)\n");
        return;
    }

    // Step 9: Strip padding
    int payload_len = enc_len - 2;
    uint8_t* payload = dec_data + 2;
    while (payload_len > 0 && payload[payload_len - 1] == 0x2F) {
        payload_len--;
    }

    // Step 10: Output decrypted payload
    printf("\nDecrypted Payload (human-readable hex, OMS Vol. 2 format):\n");
    for (int i = 0; i < payload_len; i++) {
        if (i > 0 && i % 16 == 0) printf("\n");
        printf("%02X ", payload[i]);
    }
    printf("\n");

    // Optional: Print unencrypted data
    int unenc_start = pos + enc_len;
    int unenc_len = sizeof(telegram) - unenc_start;
    if (unenc_len > 0) {
        printf("\nUnencrypted data after payload:\n");
        for (int i = 0; i < unenc_len; i++) {
            if (i > 0 && i % 16 == 0) printf("\n");
            printf("%02X ", telegram[unenc_start + i]);
        }
        printf("\n");
    }
}

extern "C" void app_main() {
    decrypt_wmbus_telegram();
}
