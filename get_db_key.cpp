#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "json.hpp"

using json = nlohmann::json;

// Read file into string
std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) throw std::runtime_error("Cannot open file: " + path);
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Base64 decode
std::vector<BYTE> base64_decode(const std::string& encoded) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr))
        throw std::runtime_error("Base64 decode length failed");

    std::vector<BYTE> decoded(len);
    if (!CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64, decoded.data(), &len, nullptr, nullptr))
        throw std::runtime_error("Base64 decode failed");

    return decoded;
}

// DPAPI decrypt
std::vector<BYTE> decrypt_dpapi(const std::vector<BYTE>& encrypted) {
    DATA_BLOB inBlob, outBlob;
    inBlob.pbData = const_cast<BYTE*>(encrypted.data());
    inBlob.cbData = static_cast<DWORD>(encrypted.size());

    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob))
        throw std::runtime_error("DPAPI decryption failed");

    std::vector<BYTE> result(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return result;
}

// Convert hex string to byte vector
std::vector<BYTE> hex_to_bytes(const std::string& hex) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        BYTE byte = static_cast<BYTE>(std::stoi(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// AES-GCM decryption using OpenSSL
std::string aes_gcm_decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& nonce,
                            const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1)
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex (key/nonce) failed");

    std::vector<BYTE> plaintext(ciphertext.size());
    int len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) != 1)
        throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) throw std::runtime_error("EVP_DecryptFinal_ex failed (authentication error)");

    return std::string(plaintext.begin(), plaintext.end());
}

// Main logic
std::string get_key(const std::string& appdir) {
    json config = json::parse(read_file(appdir + "\\config.json"));
    std::string encrypted_key_hex = config["encryptedKey"];

    json local_state = json::parse(read_file(appdir + "\\Local State"));
    std::string pw_b64 = local_state["os_crypt"]["encrypted_key"];
    std::vector<BYTE> encrypted_pw = base64_decode(pw_b64);

    std::vector<BYTE> dpapi_data(encrypted_pw.begin() + 5, encrypted_pw.end());
    std::vector<BYTE> key = decrypt_dpapi(dpapi_data);

    std::vector<BYTE> encrypted_key = hex_to_bytes(encrypted_key_hex);

    if (encrypted_key.size() != 3 + 12 + 64 + 16)
        throw std::runtime_error("Invalid encrypted key size");

    std::vector<BYTE> nonce(encrypted_key.begin() + 3, encrypted_key.begin() + 15);
    std::vector<BYTE> ciphertext(encrypted_key.begin() + 15, encrypted_key.begin() + 79);
    std::vector<BYTE> tag(encrypted_key.begin() + 79, encrypted_key.end());

    return aes_gcm_decrypt(key, nonce, ciphertext, tag);
}

int main() {
    try {
        char userprofile[MAX_PATH];
		DWORD len = GetEnvironmentVariableA("USERPROFILE", userprofile, sizeof(userprofile));
		if (len == 0 || len > sizeof(userprofile))
			throw std::runtime_error("Failed to retrieve USERPROFILE from environment");

		std::string path_to_sig = std::string(userprofile) + "\\AppData\\Roaming\\Signal";
        std::string db_key = get_key(path_to_sig);
        std::cout << "Decryption Key: " << db_key << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}