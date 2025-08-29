#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define PORT 5555
#define KEM_ALG "ML-KEM-768"
#define BUFFER_SIZE 1024

// Simple XOR for demonstration
void xor_crypt(uint8_t *msg, size_t msg_len, uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < msg_len; i++) {
        msg[i] ^= key[i % key_len];
    }
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    clock_t start, end;

    // 1️⃣ Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        return -1;
    }
    printf("Connected to server\n");

    // 2️⃣ Initialize PQC KEM
    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    uint8_t *client_pk = malloc(kem->length_public_key);
    uint8_t *client_sk = malloc(kem->length_secret_key);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);

    // Benchmark key generation
    start = clock();
    OQS_KEM_keypair(kem, client_pk, client_sk);
    end = clock();
    printf("⏱ Keypair generation: %.4f ms\n", ((double)(end - start) / CLOCKS_PER_SEC) * 1000);

    // 3️⃣ Send client public key
    write(sock, client_pk, kem->length_public_key);

    // 4️⃣ Receive ciphertext from server
    read(sock, ciphertext, kem->length_ciphertext);

    // Benchmark decapsulation
    start = clock();
    OQS_KEM_decaps(kem, shared_secret, ciphertext, client_sk);
    end = clock();
    printf("⏱ Decapsulation: %.4f ms\n", ((double)(end - start) / CLOCKS_PER_SEC) * 1000);

    printf("✅ PQC shared secret established\n");

    // 5️⃣ Messaging loop
    while (1) {
        printf("Client: ");
        fflush(stdout);
        fgets(buffer, BUFFER_SIZE, stdin);
        size_t msg_len = strcspn(buffer, "\n");
        buffer[msg_len] = '\0';

        xor_crypt((uint8_t *)buffer, msg_len, shared_secret, kem->length_shared_secret);
        write(sock, buffer, msg_len);

        int n = read(sock, buffer, BUFFER_SIZE);
        if (n <= 0) {
            printf("Server disconnected\n");
            break;
        }
        xor_crypt((uint8_t *)buffer, n, shared_secret, kem->length_shared_secret);
        buffer[n] = '\0';
        printf("Server: %s\n", buffer);
    }

    free(client_pk); free(client_sk); free(shared_secret); free(ciphertext);
    OQS_KEM_free(kem);
    close(sock);

    return 0;