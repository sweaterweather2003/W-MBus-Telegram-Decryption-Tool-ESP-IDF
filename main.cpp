#include <mbedtls/aes.h>  // Built-in for Arduino-ESP32 in Wokwi

// Hardcoded inputs (full 162 bytes, uppercase hex for consistency)
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

void setup() {
  Serial.begin(115200);
  delay(1000);

  // Step 1: Parse DLL header
  if (telegram[0] != 0xA1 || telegram[1] != 0x44) {
    Serial.println("Error: Invalid L or C field");
    return;
  }
  uint8_t M[2] = {telegram[2], telegram[3]};
  uint8_t ID[4] = {telegram[4], telegram[5], telegram[6], telegram[7]};
  uint8_t V = telegram[8];
  uint8_t D = telegram[9];

  Serial.println("Parsed DLL Header:");
  Serial.print("Manufacturer: 0x"); Serial.print(M[0], HEX); Serial.println(M[1], HEX);
  Serial.print("ID (Serial): 0x"); for (int i = 0; i < 4; i++) { Serial.print(ID[i], HEX); } Serial.println();
  Serial.print("Version: 0x"); Serial.println(V, HEX);
  Serial.print("Device Type: 0x"); Serial.println(D, HEX);

  // Step 2: Check for ELL (Extended Link Layer)
  int pos = 10;  // After DLL A-field
  uint8_t ell_ci = telegram[pos];
  uint8_t ell_cc = 0, ell_acc = 0;
  int ell_len = 0;
  if (ell_ci == 0x8C) {
    ell_len = 2;
    ell_cc = telegram[pos + 1];
    ell_acc = telegram[pos + 2];
    pos += 1 + ell_len;
    Serial.println("ELL Present:");
    Serial.print("ELL-CC: 0x"); Serial.println(ell_cc, HEX);
    Serial.print("ELL-ACC/SN: 0x"); Serial.println(ell_acc, HEX);
  } else {
    Serial.println("No ELL.");
  }

  // Step 3: Parse TPL (Transport Layer)
  uint8_t tpl_ci = telegram[pos];
  if (tpl_ci != 0x7A) {
    Serial.println("Error: Unexpected TPL-CI (expected 0x7A for short TPL)");
    return;
  }
  pos++;
  uint8_t tpl_acc = telegram[pos++];
  uint8_t tpl_sts = telegram[pos++];
  uint8_t cfg_l = telegram[pos++];
  uint8_t cfg_h = telegram[pos++];
  uint16_t cfg = (cfg_h << 8) | cfg_l;

  Serial.println("Parsed TPL Header:");
  Serial.print("TPL-ACC: 0x"); Serial.println(tpl_acc, HEX);
  Serial.print("TPL-STS: 0x"); Serial.println(tpl_sts, HEX);
  Serial.print("Config Field: 0x"); Serial.println(cfg, HEX);

  // Step 4: Determine N (bits 7-4 of LSB in config)
  int N = (cfg_l >> 4) & 0x0F;
  int enc_len = N * 16;
  if (enc_len == 0) {
    Serial.println("No encryption (N=0)");
    return;
  }
  if (pos + enc_len > sizeof(telegram)) {
    Serial.println("Error: Invalid encrypted length");
    return;
  }
  Serial.print("Encrypted blocks (N): "); Serial.print(N); Serial.print(" (length: "); Serial.print(enc_len); Serial.println(" bytes)");

  // Step 5: Build IV for mode 5: M + ID + V + D + TPL-ACC repeated x8
  uint8_t iv[16] = {M[0], M[1], ID[0], ID[1], ID[2], ID[3], V, D, tpl_acc, tpl_acc, tpl_acc, tpl_acc, tpl_acc, tpl_acc, tpl_acc, tpl_acc};

  Serial.print("IV: ");
  for (int i = 0; i < 16; i++) {
    Serial.print(iv[i], HEX); Serial.print(" ");
  }
  Serial.println();

  // Step 6: Extract encrypted data (starts at current pos)
  uint8_t enc_data[enc_len];
  memcpy(enc_data, &telegram[pos], enc_len);

  // Step 7: Decrypt using mbedtls AES-128-CBC
  uint8_t dec_data[enc_len];
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  if (mbedtls_aes_setkey_dec(&ctx, key, 128) != 0) {
    Serial.println("Error: AES setkey failed");
    return;
  }
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);
  if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, enc_len, iv_copy, enc_data, dec_data) != 0) {
    Serial.println("Error: AES decryption failed");
    mbedtls_aes_free(&ctx);
    return;
  }
  mbedtls_aes_free(&ctx);

  // Step 8: Verify leading 0x2F 0x2F
  if (dec_data[0] != 0x2F || dec_data[1] != 0x2F) {
    Serial.println("Error: Invalid decryption (missing leading 0x2F 0x2F)");
    return;
  }

  // Step 9: Strip leading verification (2 bytes) and trailing 0x2F padding
  int payload_len = enc_len - 2;
  uint8_t* payload = dec_data + 2;
  while (payload_len > 0 && payload[payload_len - 1] == 0x2F) {
    payload_len--;
  }

  // Step 10: Output decrypted payload in human-readable hex format
  Serial.println("\nDecrypted Payload (human-readable hex, OMS Vol. 2 format):");
  for (int i = 0; i < payload_len; i++) {
    if (i > 0 && i % 16 == 0) Serial.println();
    Serial.print(payload[i], HEX); Serial.print(" ");
  }
  Serial.println();

  // Optional: Print unencrypted data if any (after encrypted payload)
  int unenc_start = pos + enc_len;
  int unenc_len = sizeof(telegram) - unenc_start;
  if (unenc_len > 0) {
    Serial.println("\nUnencrypted data after payload:");
    for (int i = 0; i < unenc_len; i++) {
      if (i > 0 && i % 16 == 0) Serial.println();
      Serial.print(telegram[unenc_start + i], HEX); Serial.print(" ");
    }
    Serial.println();
  }
}

void loop() {
  // Empty; runs once
}
