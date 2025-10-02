# W-MBus-Telegram-Decryption-Tool-ESP-IDF
This project implements the decryption of a Wireless M-Bus (W-MBus) telegram using AES-128-CBC, following the Open Metering System (OMS) Volume 2 standard for data protection (Security Mode 5). The implementation is written in C++ and is designed to run on ESP-IDF using a ESP32 Dev Kit.

## Overview

The implementation is written in C++ and is designed to run on ESP-IDF, using a ESP32 dev kit.

The code parses the telegram header (DLL, optional ELL, TPL), constructs the initialization vector (IV), decrypts the encrypted payload, verifies the leading filler bytes (0x2F 0x2F), strips trailing padding (0x2F), and outputs the decrypted payload in human-readable hex format.

## W-MBus Telegram Structure

The W-MBus telegram follows the EN 13757-3 and OMS Vol. 2 specifications. A typical unidirectional SND-NR frame structure includes:

- **Data Link Layer (DLL)**: Starts with L-field (length), C-field (control, e.g., 0x44 for SND-NR), M-field (manufacturer ID, 2 bytes), A-field (address: ID 4 bytes + Version 1 byte + Device Type 1 byte).
- **Extended Link Layer (ELL)**: Optional, indicated by CI=0x8C at position 10, followed by CC (communication counter) and ACC/SN (access number or session number).
- **Transport Layer (TPL)**: CI-field (e.g., 0x7A for short encrypted header), ACC (access number), STS (status), 2-byte configuration field (encryption mode and block count).
- **Application Layer (APL)**: Encrypted payload (multiple of 16 bytes), starting after TPL, with length determined by N (bits 7-4 of config low byte) * 16 bytes.
- **Padding and Verification**: Decrypted payload starts with 0x2F 0x2F (verification bytes) and may end with 0x2F padding.

For the sample telegram:
- DLL: L=0xA1, C=0x44, M=0xC514, ID=0x27858950, V=0x70, D=0x07 (water meter).
- ELL: CI=0x8C, CC=0x20, ACC=0x60.
- TPL: CI=0x7A, ACC=0x9D, STS=0x00, Config=0x2590 (Mode 5, N=9 blocks = 144 bytes encrypted).

## AES-128 Decryption Steps (Aligned with OMS Volume 2)

The decryption follows OMS Vol. 2 Section 9.3.5 (Security Profile 5: AES-128 CBC with dynamic IV, no authentication):

1. **Parse Header**: Extract M, ID, V, D from DLL; check for ELL (CI=0x8C); parse TPL (CI=0x7A), extract ACC, STS, Config.
2. **Determine Encrypted Length**: N = (config_low >> 4) & 0x0F; enc_len = N * 16. (Table 19 in OMS Vol. 2 for config field bits.)
3. **Construct IV (16 bytes)**: M (2 bytes) + ID (4 bytes) + V (1 byte) + D (1 byte) + TPL ACC repeated 8 times (Sec. 9.3.2).
4. **Extract Encrypted Payload**: Starting after config field.
5. **Decrypt**: Use AES-128-CBC decryption with the provided key and IV (using mbedTLS library on ESP32).
6. **Verify**: Check if decrypted data starts with 0x2F 0x2F (filler bytes, Sec. 9.3.3); if not, error.
7. **Strip Padding**: Remove leading 2 bytes (0x2F 0x2F) and trailing 0x2F bytes.
8. **Output**: Print the decrypted payload as hex, which typically contains DIF/VIF-coded meter data (e.g., volume readings).

No MIC or KDF is used in Mode 5.

## How to Build and Run the Code

### On Real ESP32 

1. Install VS Code and add ESP-IDF extension.
2. Connect ESP32 to PC/Laptop via USB.
3. Paste the code into a new sketch.
4. Download the files from GitHub: Go to github.com/kokke/tiny-AES-c and paste it into a folder called components
5. Select ESP32 board and port, build flash and monitor.
6. Open Serial Monitor at 115200 baud to see output.

## Example Input and Output

### Input

- AES-128 Key: `4255794d3dccfd46953146e701b7db68` (hex)
- Encrypted Telegram: `a144c5142785895070078c20607a9d00902537ca231fa2da5889be8df3673ec136aebfb80d4ce395ba98f6b3844a115e4be1b1c9f0a2d5ffbb92906aa388deaa82c929310e9e5c4c0922a784df89cf0ded833be8da996eb5885409b6c9867978dea24001d68c603408d758a1e2b91c42ebad86a9b9d287880083bb0702850574d7b51e9c209ed68e0374e9b01feb fd92b4cb9410fdeaf7fb526b742dc9a8d0682653` (hex, 162 bytes)

### Output

<img width="1156" height="864" alt="image" src="https://github.com/user-attachments/assets/dce7bedb-2f1f-4866-9284-f06505e5316a" />
 
