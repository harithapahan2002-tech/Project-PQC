#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <time.h>

#define PORT 5555
#define KEM_ALG "ML-KEM-768"
#define BUFFER_SIZE 1024

// Simple XOR for demonstration
void xor_crypt(uint8_t *msg, size_t msg_len, uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < msg_len; i++) {
        msg[i] ^= key[i % key_len];
    }
}

// Helper to get time in microseconds
double elapsed_time_us(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e6 +
           (end.tv_nsec - start.tv_nsec) / 1e3;
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    char buffer[BUFFER_SIZE];
    struct timespec start, end;

    // 1️⃣ Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) { perror("socket failed"); exit(EXIT_FAILURE); }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 2️⃣ Bind
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed"); exit(EXIT_FAILURE);
    }

    // 3️⃣ Listen
    if (listen(server_fd, 1) < 0) { perror("listen"); exit(EXIT_FAILURE); }
    printf("Server listening on port %d\n", PORT);

    // 4️⃣ Accept client
    client_fd = accept(server_fd, (struct sockaddr *)&address, &addr_len);
    if (client_fd < 0) { perror("accept"); exit(EXIT_FAILURE); }
    printf("Client connected\n");

    // 5️⃣ Initialize PQC KEM
    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    uint8_t *server_pk = malloc(kem->length_public_key);
    uint8_t *server_sk = malloc(kem->length_secret_key);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);

    // Benchmark: Keypair generation
    clock_gettime(CLOCK_MONOTONIC, &start);
    OQS_KEM_keypair(kem, server_pk, server_sk);
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("⏱ Keypair generation time: %.2f µs\n", elapsed_time_us(start, end));

    // 6️⃣ Receive client public key
    uint8_t client_pk[kem->length_public_key];
    read(client_fd, client_pk, kem->length_public_key);

    // Benchmark: Encapsulation
    clock_gettime(CLOCK_MONOTONIC, &start);
    OQS_KEM_encaps(kem, ciphertext, shared_secret, client_pk);
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("⏱ Encapsulation time: %.2f µs\n", elapsed_time_us(start, end));

    // Send ciphertext to client
    write(client_fd, ciphertext, kem->length_ciphertext);

    printf("✅ PQC shared secret established\n");

    // 8️⃣ Bidirectional messaging
    while (1) {
        // Receive message from client
        int n = read(client_fd, buffer, BUFFER_SIZE);
        if (n <= 0) {
            printf("Client disconnected\n");
            break;
        }

        // Benchmark: Decryption (XOR)
        clock_gettime(CLOCK_MONOTONIC, &start);
        xor_crypt((uint8_t *)buffer, n, shared_secret, kem->length_shared_secret);
        clock_gettime(CLOCK_MONOTONIC, &end);
        printf("⏱ Message decryption time: %.2f µs\n", elapsed_time_us(start, end));

        buffer[n] = '\0';
        printf("Client: %s\n", buffer);

        // Send reply
        printf("Server: ");
        fflush(stdout);
        fgets(buffer, BUFFER_SIZE, stdin);
        size_t msg_len = strcspn(buffer, "\n"); // remove newline
        buffer[msg_len] = '\0';

        // Benchmark: Encryption (XOR)
        clock_gettime(CLOCK_MONOTONIC, &start);
        xor_crypt((uint8_t *)buffer, msg_len, shared_secret, kem->length_shared_secret);
        clock_gettime(CLOCK_MONOTONIC, &end);
        printf("⏱ Message encryption time: %.2f µs\n", elapsed_time_us(start, end));

        write(client_fd, buffer, msg_len);
    }

    free(server_pk); free(server_sk); free(shared_secret); free(ciphertext);
    OQS_KEM_free(kem);
    close(client_fd); close(server_fd);

    return 0;
}