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

int Receive_buffer(int cid, unsigned char* buffer,int size)
{
    size_t totalReceived = 0;
    size_t length=size;
    while (totalReceived < length) {
        ssize_t received = recv(cid, buffer + totalReceived, length - totalReceived, 0);
        if (received == -1) {
            //cerr << "Error receiving data: " << strerror(errno) << endl;
            return -1;
        } else if (received == 0) {
            //cerr << "Connection closed by peer" << endl;
            return 0;
        }
        totalReceived += received;
    }
    return totalReceived;
}

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

////////////////////////////////

void generate_pn_sequence(int *pn_sequence, int length , int seed) {
    srand(seed);
    for (int i = 0; i < length; ++i) {
        pn_sequence[i] = rand() % 2 == 0 ? 1 : -1;
    }
}

void bit_sequence_to_text(int *bit_sequence, int bit_sequence_length, char *plaintext) {
    int text_length = bit_sequence_length / 8; 
    for (int i = 0; i < text_length; ++i) {
        int char_code = 0;
        for (int j = 0; j < 8; ++j) {
            if (bit_sequence[i * 8 + j] == -1) { 
                bit_sequence[i * 8 + j] = 0;
            }
            char_code += (bit_sequence[i * 8 + j] << (7 - j));
        }
        plaintext[i] = (char)char_code; 
    }
    plaintext[text_length] = '\0'; 
}

void vigenere_decrypt(char *ciphertext, char *key) {
    int i, j;
    int ciphertext_len = strlen(ciphertext);
    int key_len = strlen(key);
    for (i = 0, j = 0; i < ciphertext_len; ++i, ++j) {
        if (j == key_len) {
            j = 0;
        }
        ciphertext[i] = ((ciphertext[i] - 'a') - (key[j] - 'a') + 26) % 26 + 'a';
    }
}

int main(int argc , char *argv[]) {

int client_socket;
    struct sockaddr_in server_addr;

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        handle_error("socket creation error\n");
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    //server_addr.sin_addr.s_addr = inet_addr("abc.de.fgh.ijk");//Edit it to the sender's(Client's) IP address
    server_addr.sin_addr.s_addr = INADDR_ANY ;//Delete this line after you add the senders address above.
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        handle_error("Error connecting to server");
    }

    printf("Connected to server\n");

    
    // Receive encrypted message and hash from client
    unsigned char encrypted_msg1[BUFSIZE];
    unsigned char received_hash1[SHA256_DIGEST_LENGTH];
    unsigned char encrypted_msg2[BUFSIZE];
    unsigned char received_hash2[SHA256_DIGEST_LENGTH];
    unsigned char encrypted_msg3[BUFSIZE];
    unsigned char received_hash3[SHA256_DIGEST_LENGTH];
    unsigned char encrypted_msg4[BUFSIZE];
    unsigned char received_hash4[SHA256_DIGEST_LENGTH];
    
    Receive_buffer(client_socket, encrypted_msg1, sizeof(encrypted_msg1) );
    Receive_buffer(client_socket, received_hash1, sizeof(received_hash1) );
    
    Receive_buffer(client_socket, encrypted_msg2, sizeof(encrypted_msg2));
    Receive_buffer(client_socket, received_hash2, sizeof(received_hash2));
    
    printf("%d\n" , Receive_buffer(client_socket, encrypted_msg3, sizeof(encrypted_msg3)));
    printf("%d\n" , Receive_buffer(client_socket, received_hash3, sizeof(received_hash3)));
    
    printf("%d\n" , Receive_buffer(client_socket, encrypted_msg4, sizeof(encrypted_msg4)));
    printf("%d\n" , Receive_buffer(client_socket, received_hash4, sizeof(received_hash4)));

    // Calculate hash of received message
    unsigned char calculated_hash1[SHA256_DIGEST_LENGTH];
    calculate_sha256(encrypted_msg1, sizeof(encrypted_msg1), calculated_hash1);
    
    unsigned char calculated_hash2[SHA256_DIGEST_LENGTH];
    calculate_sha256(encrypted_msg2, sizeof(encrypted_msg2), calculated_hash2);
    
    unsigned char calculated_hash3[SHA256_DIGEST_LENGTH];
    calculate_sha256(encrypted_msg3, sizeof(encrypted_msg3), calculated_hash3);
    
     unsigned char calculated_hash4[SHA256_DIGEST_LENGTH];
    calculate_sha256(encrypted_msg4, sizeof(encrypted_msg4), calculated_hash4);
    
    unsigned char decrypted_msg1[BUFSIZE];
    unsigned char decrypted_msg2[BUFSIZE];
    unsigned char decrypted_msg3[BUFSIZE];
    unsigned char decrypted_msg4[BUFSIZE];

    // Compare received hash with calculated hash
    if (memcmp(received_hash1, calculated_hash1, SHA256_DIGEST_LENGTH) == 0) {
        printf("Hashes match. Decrypting message...\n");

        // Decrypt the message
        aes_decrypt(encrypted_msg1, sizeof(encrypted_msg1), "encryptionKey123", decrypted_msg1);

        //printf("Received Message: %s\n", encrypted_msg);
        /*printf("printing the received Message (Hex): \n");
		for (int i = 0; i < sizeof(encrypted_msg1); i++) {
    		printf("%02x", encrypted_msg1[i]);
		}
		printf("\n");

        printf("printing the received Hash: \n");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", received_hash1[i]);
        }
        printf("\n");
        printf("Calculated Hash: \n");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", calculated_hash1[i]);
        }
        printf("\n");*/
        printf("Decrypted Message: %s\n", decrypted_msg1);
    } else {
        printf("Hashes do not match. Message may be tampered.\n");
    }
    
    if (memcmp(received_hash2, calculated_hash2, SHA256_DIGEST_LENGTH) == 0) {
        printf("Hashes match. Decrypting message...\n");

        // Decrypt the message
        aes_decrypt(encrypted_msg2, sizeof(encrypted_msg2), "encryptionKey123", decrypted_msg2);

        //printf("Received Message: %s\n", encrypted_msg);
        /*printf("printing the received Message (Hex): \n");
		for (int i = 0; i < sizeof(encrypted_msg2); i++) {
    		printf("%02x", encrypted_msg2[i]);
		}
		printf("\n");

        printf("printing the received Hash: \n");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", received_hash2[i]);
        }
        printf("\n");
        printf("Calculated Hash: \n");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", calculated_hash2[i]);
        }
        printf("\n");
        */
        printf("Decrypted Message: %s\n", decrypted_msg2);
    } else {
        printf("Hashes do not match. Message may be tampered.\n");
    }
    
    if (memcmp(received_hash3, calculated_hash3, SHA256_DIGEST_LENGTH) == 0) {
        printf("Hashes match. Decrypting message...\n");

        // Decrypt the message
        aes_decrypt(encrypted_msg3, sizeof(encrypted_msg3), "encryptionKey123", decrypted_msg3);

        //printf("Received Message: %s\n", encrypted_msg);
        /*printf("printing the received Message (Hex): \n");
		for (int i = 0; i < sizeof(encrypted_msg3); i++) {
    		printf("%02x", encrypted_msg3[i]);
		}
		printf("\n");

        printf("printing the received Hash: \n");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", received_hash3[i]);
        }
        printf("\n");
        printf("Calculated Hash: \n");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", calculated_hash3[i]);
        }
        printf("\n");*/
        printf("Decrypted Message: %s\n", decrypted_msg3);
    } else {
        printf("Hashes do not match. Message may be tampered.\n");
    }
    
    
    if (memcmp(received_hash4, calculated_hash4, SHA256_DIGEST_LENGTH) == 0) {
        printf("Hashes match. Decrypting message...\n");

        // Decrypt the message
        aes_decrypt(encrypted_msg4, sizeof(encrypted_msg4), "encryptionKey123", decrypted_msg4);

        //printf("Received Message: %s\n", encrypted_msg);
        /*printf("printing the received Message (Hex): \n");
		for (int i = 0; i < sizeof(encrypted_msg4); i++) {
    		printf("%02x", encrypted_msg4[i]);
		}
		printf("\n");

        printf("printing the received Hash: \n");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", received_hash4[i]);
        }
        printf("\n");
        printf("Calculated Hash: \n");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", calculated_hash4[i]);
        }
        printf("\n");*/
        printf("Decrypted Message: %s\n", decrypted_msg4);
    } else {
        printf("Decrypted Message: %s\n", decrypted_msg4);
        printf("Hashes do not match. Message may be tampered.\n");
    }

    close(client_socket);
    
    //<------------------------------------EXTRACTING THE MESSAGE--------------------------------------------------->

   int cr = atoi(decrypted_msg1) ; int l = atoi(decrypted_msg2) ; int seed = atoi(decrypted_msg3); char *key = decrypted_msg4 ; 
   //scanf("%d" , &cr) ;
   //scanf("%d" , &l) ;
   //scanf("%ld" , &seed) ;
   int message_length = l ;
   //char plaintext[100];
   int* pn_sequence = (int*)malloc(message_length*sizeof(int));
   int* message = (int*)malloc((l/cr)*sizeof(int));
   generate_pn_sequence(pn_sequence , l , seed) ; 
   printf("pn sequence is generated is : \n");
   for(int i = 0; i<l ; i++){
     printf("%d " , pn_sequence[i]) ;
   }
   printf("\nThe length of the pn sequence generated is : %d\n\n" , l) ;
   const char *input_filename = argv[1];
   SNDFILE *input_file ;

   SF_INFO sfinfo;   

    input_file = sf_open(input_filename, SFM_READ, &sfinfo);
    if (!input_file) {
        printf("Error opening input file\n");
        return 1;
    }
    float* ds = (float*)malloc(l*sizeof(int));  ;
    int count = 0 ;
    float buffer[BUFFER_LEN];
    sf_count_t read_count;
    printf("The ampitudes of the samples from the modified output audio file are \n:") ;
    while ((read_count = sf_read_float(input_file, buffer, BUFFER_LEN))) {
        //printf("%d\n" , 0) ;
        if(count < l){
          printf("%f " , buffer[0]) ;
          ds[count] = buffer[0]*10 ;
        }
        count++ ;
        // Write modified buffer to output file
    }
    printf("\n") ;
    int length = 0 ;
    //while(length < l){
      // printf("%f ", ds[length]) ;
       //length++ ;
    //}
    //printf("%d\n" , length) ; 
    for(int i = 0 ; i<l/cr ; i++){
       float val = 0 ;
       for(int j = 0 ; j<cr ; j++){
         val = val + ds[i*cr + j]*pn_sequence[i*cr + j] ;
       }
       if(val > 0)message[i] = 1 ;
       else message[i] = -1 ;
    }
    length = 0 ;
    printf("The final extracted bit sequence of the message is : \n") ;
    while(message[length] != NULL){
        if(length%8==0)printf("\n");
       printf("%d ", message[length]) ;
       length++ ;
    }
    printf("\n") ;
    char *plaintext = (char *)malloc((l/cr*8 + 1) * sizeof(char));
    // Convert the bit sequence to plaintext
    bit_sequence_to_text(message, l/cr , plaintext);
    printf("Plaintext: %s\n", plaintext);
    //char key[] = "abcd"; 
    vigenere_decrypt(plaintext, key);
    printf("Decrypted plaintext: %s\n", plaintext);

    return 0 ;
}
