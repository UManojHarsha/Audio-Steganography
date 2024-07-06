#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <sndfile.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define BUFFER_LEN 1024
#define BUFSIZE 1024
#define AES_KEY_SIZE 128

void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void calculate_sha256(const unsigned char *data, size_t len, unsigned char *hash) {
    SHA256(data, len, hash);
}

void aes_encrypt(const unsigned char *input, int input_len, const unsigned char *key, unsigned char *output) {
    AES_KEY enc_key;
    AES_set_encrypt_key(key, AES_KEY_SIZE, &enc_key);
    AES_encrypt(input, output, &enc_key);
}

void aes_decrypt(const unsigned char *input, int input_len, const unsigned char *key, unsigned char *output) {
    AES_KEY dec_key;
    AES_set_decrypt_key(key, AES_KEY_SIZE, &dec_key);
    AES_decrypt(input, output, &dec_key);
}

void vigenere_encrypt(char *plaintext, char *key) {
    int i, j;
    int plaintext_len = strlen(plaintext);
    int key_len = strlen(key);

    for (i = 0, j = 0; i < plaintext_len; ++i, ++j) {
    
        if (j == key_len) {
            j = 0;
        }
        
        plaintext[i] = ((plaintext[i] - 'a') + (key[j] - 'a')) % 26 + 'a';
    }
}

void text_to_bit_sequence(char *plaintext, int *bit_sequence) {
    int i, j;
    int plaintext_len = strlen(plaintext);

    for (i = 0; i < plaintext_len; ++i) {
        
        for (j = 0; j < 8; ++j) {
            
            bit_sequence[i * 8 + j] = (plaintext[i] >> (7 - j)) & 1;
            if(bit_sequence[i * 8 + j] == 0)bit_sequence[i * 8 + j] = -1 ;
            printf("%d ",bit_sequence[i * 8 + j]) ;
        }
        printf("\n") ;
    }
}

void generate_pn_sequence(int *pn_sequence, int length, long seed) {

    srand(seed);

    for (int i = 0; i < length; ++i) {
        pn_sequence[i] = rand() % 2 == 0 ? 1 : -1;
    }
}

void modulate_signal(int *message_signal, int *pn_sequence, int *distributed_signal, int message_length, int cr) {
    
    for (int i = 0; i < message_length; ++i) {
        for (int j = 0; j < cr; ++j) {
            distributed_signal[i*cr + j] = message_signal[i] * pn_sequence[i*cr + j];
        }
    }
    
}

int main(int argc , char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }
    
    /*<-------------------------------------------------ENCRYPTION--------------------------------------------------------->*/
    
    int message_length;
    int cr;

    char plaintext[100], key[100];
    int bit_sequence[800]; 
    long seed;
    int *pn_sequence;
    int *distributed_signal;
    
    
    printf("Enter plaintext: ");
    scanf("%s", plaintext);
    printf("Enter key: ");
    scanf("%s", key);
    
    printf("\n") ;
    
    vigenere_encrypt(plaintext, key);
    
    printf("The vigenere encrypted cipher text is : ") ;
    
    for(int i = 0 ; i<strlen(plaintext) ; i++){
      printf("%c" , plaintext[i]) ;
    }
    printf("\n") ;

    
    text_to_bit_sequence(plaintext, bit_sequence);
    message_length = strlen(plaintext) * 8;

    printf("Enter secret seed number: ");
    scanf("%ld", &seed);
    printf("Enter chip rate (cr): ");
    scanf("%d", &cr);

    printf("\n") ;
    pn_sequence = (int *)malloc(message_length * cr * sizeof(int));
    distributed_signal = (int *)malloc(message_length * cr * sizeof(int));

    generate_pn_sequence(pn_sequence, message_length*cr , seed);
    
    int length = 0 ;
    printf("pn sequence generated is : \n");
    while(pn_sequence[length] != NULL){
       printf("%d ", pn_sequence[length]) ;
       length++ ;
    }
    printf("\n") ;
    printf("Length of pn sequence is : %d\n\n\n" , length) ;
    
    
    length = 0 ;
    printf("The message after converted into bits is : \n");
    while(bit_sequence[length] != NULL){
       printf("%d ", bit_sequence[length]) ;
       length++ ;
    }
    printf("\n") ;
    printf("Length of the bit sequence of the message is : %d\n\n\n" , length) ;
    

    modulate_signal(bit_sequence, pn_sequence, distributed_signal, length , cr);
    
    int final_length = 0 ;
    printf("The final distributed signal is : \n");
    while(distributed_signal[final_length] != NULL){
       printf("%d ",distributed_signal[final_length]) ;
       final_length++ ;
    }
    printf("\n") ;
    printf("The length of distributed signal is %d\n\n\n" , final_length) ;
    
    /*<-----------------------------------------AUDIO WORK------------------------------------------------------>*/
    
    const char *input_filename = argv[1];
    const char *output_filename = argv[2];

    SNDFILE *input_file, *output_file;
    SF_INFO sfinfo;

    input_file = sf_open(input_filename, SFM_READ, &sfinfo);
    if (!input_file) {
        printf("Error opening input file\n");
        return 1;
    }

    output_file = sf_open(output_filename, SFM_WRITE, &sfinfo);
    if (!output_file) {
        printf("Error opening output file\n");
        sf_close(input_file);
        return 1;
    }
    
    //printf("Sample rate: %d Hz\n", sfinfo.samplerate);


    float buffer[BUFFER_LEN];
    sf_count_t read_count;
    int count = 0 ;
    
    printf("The amplitudes of the audio samples that have to be modified are : \n");
    while ((read_count = sf_read_float(input_file, buffer, BUFFER_LEN))) {
    
        if(count < final_length){
           //printf("%f %d ", buffer[0] ,distributed_signal[count]) ;
           buffer[0] = (buffer[0] + distributed_signal[count])/10 ;
           printf("%f " , buffer[0]) ;
        }
        count++ ;

        // Write modified buffer to output file
        sf_write_float(output_file, buffer, read_count);
    }
    printf("\n") ;
    
    sf_close(input_file);
    sf_close(output_file);
    
    
    
    
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        handle_error("socket creation error");
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        handle_error("Error binding socket");
    }

    if (listen(server_socket, 5) == -1) {
        handle_error("Error listening");
    }

    if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len)) == -1) {
        handle_error("Error accepting connection");
    }

    printf("client got connection with server\n");
    // Take input message
    char input_msg1[BUFSIZE] ;
    char input_msg2[BUFSIZE] ;
    char input_msg3[BUFSIZE] ;
    char input_msg4[BUFSIZE] ;
    
    sprintf(input_msg1 , "%d", cr);
    input_msg1[strcspn(input_msg1, "\n")] = 0;  // Remove newline character
    
    sprintf(input_msg2 , "%d", final_length);
    input_msg2[strcspn(input_msg2, "\n")] = 0;  // Remove newline character
    
    sprintf(input_msg3 , "%d", seed);
    input_msg3[strcspn(input_msg3, "\n")] = 0;  // Remove newline character
    
    

    // Encrypt the message
    unsigned char encrypted_msg1[BUFSIZE];
    unsigned char encrypted_msg2[BUFSIZE];
    unsigned char encrypted_msg3[BUFSIZE];
    unsigned char encrypted_msg4[BUFSIZE];
    
    aes_encrypt(input_msg1, strlen(input_msg1), "encryptionKey123", encrypted_msg1);
    aes_encrypt(input_msg2, strlen(input_msg2), "encryptionKey123", encrypted_msg2);
    aes_encrypt(input_msg3, strlen(input_msg3), "encryptionKey123", encrypted_msg3);
    aes_encrypt(key, strlen(key), "encryptionKey123", encrypted_msg4);

    // Calculate hash of the encrypted message
    unsigned char calculated_hash1[SHA256_DIGEST_LENGTH];
    unsigned char calculated_hash2[SHA256_DIGEST_LENGTH];
    unsigned char calculated_hash3[SHA256_DIGEST_LENGTH];
    unsigned char calculated_hash4[SHA256_DIGEST_LENGTH];
    
    calculate_sha256(encrypted_msg1, sizeof(encrypted_msg1), calculated_hash1);
    calculate_sha256(encrypted_msg2, sizeof(encrypted_msg2), calculated_hash2);
    calculate_sha256(encrypted_msg3, sizeof(encrypted_msg3), calculated_hash3);
    calculate_sha256(encrypted_msg4, sizeof(encrypted_msg4), calculated_hash4);
    
    // Send encrypted message and hash to server
    send(client_socket, encrypted_msg1, sizeof(encrypted_msg1), 0);
    send(client_socket, calculated_hash1, sizeof(calculated_hash1), 0);
    
    send(client_socket, encrypted_msg2, sizeof(encrypted_msg2), 0);
    send(client_socket, calculated_hash2, sizeof(calculated_hash2), 0);
    
    send(client_socket, encrypted_msg3, sizeof(encrypted_msg3), 0);
    send(client_socket, calculated_hash3, sizeof(calculated_hash3), 0);
    
    send(client_socket, encrypted_msg4, sizeof(encrypted_msg4), 0);
    send(client_socket, calculated_hash4, sizeof(calculated_hash4), 0);

    printf("Chip rate sent : %s\n", input_msg1);
    /*printf("printing the Encrypted Message: \n");
    for (int i = 0; i < sizeof(encrypted_msg1); i++) {
        printf("%02x", encrypted_msg1[i]);
    }
    printf("\n");
    printf("Calculated Hash: \n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", calculated_hash1[i]);
    }
    printf("\n");
    */
    printf("Distributed signal length sent : %s\n", input_msg2);
    /*printf("printing the Encrypted Message: \n");
    for (int i = 0; i < sizeof(encrypted_msg2); i++) {
        printf("%02x", encrypted_msg2[i]);
    }
    printf("\n");
    printf("Calculated Hash: \n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", calculated_hash2[i]);
    }
    printf("\n");
    */
    printf("Seed number sent : %s\n", input_msg3);
    /*printf("printing the Encrypted Message: \n");
    for (int i = 0; i < sizeof(encrypted_msg3); i++) {
        printf("%02x", encrypted_msg3[i]);
    }
    printf("\n");
    printf("Calculated Hash: \n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", calculated_hash3[i]);
    }
    printf("\n");
    */
    printf("Vigenere key sent : %s\n", key);
    /*printf("printing the Encrypted Message: \n");
    for (int i = 0; i < sizeof(encrypted_msg4); i++) {
        printf("%02x", encrypted_msg4[i]);
    }
    printf("\n");
    printf("Calculated Hash: \n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", calculated_hash4[i]);
    }
    printf("\n");
    */
    
    close(client_socket);
    close(server_socket);
    
    
    

    return 0;
}

