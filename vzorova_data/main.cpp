#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>


struct crypto_config
{
	const char * m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#endif

int encrypt_data(const std::string & in_filename, const std::string & out_filename, crypto_config & config) {
    
    std::ifstream file_to_open(in_filename, std::ios::binary);
    if(!file_to_open.is_open()){
        return EXIT_FAILURE;
    }

    char Head[18];
    file_to_open.read(Head, 18);

    if(file_to_open.gcount() != 18){
        return EXIT_FAILURE;  // Исправлено: добавлен return
    }

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        return EXIT_FAILURE;
    }

    const EVP_CIPHER * cipher_type = EVP_get_cipherbyname(config.m_crypto_function);

    if(!cipher_type){
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    size_t key_length = EVP_CIPHER_key_length(cipher_type);
    // Удалена неправильная проверка key_length < config.m_key_len

    // Проверка наличия ключа и генерация если необходимо
    if (!config.m_key || config.m_key_len < (size_t)key_length) {
        config.m_key = std::make_unique<uint8_t[]>(key_length);

        if (RAND_bytes(config.m_key.get(), key_length) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
        config.m_key_len = key_length;
    }

    size_t IV_len = EVP_CIPHER_iv_length(cipher_type);
    if ((!config.m_IV || config.m_IV_len < (size_t)IV_len) && IV_len > 0) {
        config.m_IV = std::make_unique<uint8_t[]>(IV_len);
        int res = RAND_bytes(config.m_IV.get(), IV_len);  // Изменено: ssize_t на int
        if (res != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
        config.m_IV_len = IV_len;
    }

    int res_init = EVP_EncryptInit_ex(ctx, cipher_type, nullptr, config.m_key.get(), 
                                     IV_len > 0 ? config.m_IV.get() : nullptr);
    if(res_init != 1){
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    
    int outlength;
    unsigned char buffer[1024]; 
    unsigned char output_buffer[1024 + EVP_MAX_BLOCK_LENGTH]; 

    std::ofstream output_file(out_filename, std::ios::binary);

    if(!output_file){
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    output_file.write(Head, 18);
    if (!output_file) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    while (file_to_open) {
        file_to_open.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
        int bytes_read = file_to_open.gcount();
        if (bytes_read > 0) {
            if (EVP_EncryptUpdate(ctx, output_buffer, &outlength, buffer, bytes_read) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return EXIT_FAILURE;
            }
            output_file.write(reinterpret_cast<char*>(output_buffer), outlength);
            if (!output_file) {
                EVP_CIPHER_CTX_free(ctx);
                return EXIT_FAILURE;
            }
        }
    }
 
    if (EVP_EncryptFinal_ex(ctx, output_buffer, &outlength) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    output_file.write(reinterpret_cast<char*>(output_buffer), outlength);
    if (!output_file) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    EVP_CIPHER_CTX_free(ctx);
    return EXIT_SUCCESS;
}

int decrypt_data(const std::string & in_filename, const std::string & out_filename, crypto_config & config)
{
    std::ifstream file_to_open(in_filename, std::ios::binary);
    if(!file_to_open.is_open()){
        return EXIT_FAILURE;
    }

    char Head[18];
    file_to_open.read(Head, 18);

    if(file_to_open.gcount() != 18){
        return EXIT_FAILURE;  // Исправлено: добавлен return
    }

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        return EXIT_FAILURE;
    }

    const EVP_CIPHER * cipher_type = EVP_get_cipherbyname(config.m_crypto_function);

    if(!cipher_type){
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    size_t key_length = EVP_CIPHER_key_length(cipher_type);
    // Удалена неправильная проверка key_length < config.m_key_len

    // Проверка наличия ключа достаточного размера
    if (!config.m_key || config.m_key_len < (size_t)key_length) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;  // Для дешифрования ключ должен быть уже установлен
    }

    size_t IV_len = EVP_CIPHER_iv_length(cipher_type);
    // Проверка наличия IV достаточного размера для алгоритмов, которые его используют
    if (IV_len > 0 && (!config.m_IV || config.m_IV_len < (size_t)IV_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;  // Для дешифрования IV должен быть уже установлен
    }

    int res_init = EVP_DecryptInit_ex(ctx, cipher_type, nullptr, config.m_key.get(), 
                                      IV_len > 0 ? config.m_IV.get() : nullptr);
    if(res_init != 1){
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    int outlength;
    unsigned char buffer[1024]; 
    unsigned char output_buffer[1024 + EVP_MAX_BLOCK_LENGTH]; 

    std::ofstream output_file(out_filename, std::ios::binary);

    if(!output_file){
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    output_file.write(Head, 18);
    if (!output_file) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    while (file_to_open) {
        file_to_open.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
        int bytes_read = file_to_open.gcount();
        if (bytes_read > 0) {
            if (EVP_DecryptUpdate(ctx, output_buffer, &outlength, buffer, bytes_read) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return EXIT_FAILURE;
            }
            output_file.write(reinterpret_cast<char*>(output_buffer), outlength);
            if (!output_file) {
                EVP_CIPHER_CTX_free(ctx);
                return EXIT_FAILURE;
            }
        }
    }
 
    if (EVP_DecryptFinal_ex(ctx, output_buffer, &outlength) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    output_file.write(reinterpret_cast<char*>(output_buffer), outlength);
    if (!output_file) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    EVP_CIPHER_CTX_free(ctx);
    return EXIT_SUCCESS;
}

#ifndef __PROGTEST__

bool compare_files ( const char * name1, const char * name2 )
{
	return false;
}

int main ( void )
{
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
 	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	assert( EXIT_SUCCESS == encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

	assert( EXIT_SUCCESS == decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

	assert( EXIT_SUCCESS == decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

	assert( EXIT_SUCCESS == decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

	assert( EXIT_SUCCESS == decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);

	assert( EXIT_SUCCESS == encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

	assert( EXIT_SUCCESS == decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

	assert( EXIT_SUCCESS == decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

	assert( EXIT_SUCCESS == decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

	assert( EXIT_SUCCESS == decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );
	return 0;
}

#endif
