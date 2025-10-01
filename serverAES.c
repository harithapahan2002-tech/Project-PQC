#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 5555
#define KEM_ALG "ML-KEM-768"
#define BUFFER_SIZE 4096

#define IV_LEN 12
#define TAG_LEN 16

static double elapsed_time_us(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_nsec - start.tv_nsec) / 1e3;
}

// Ensure we read n bytes unless EOF/error
static ssize_t read_exact(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (uint8_t*)buf + off, n - off);
        if (r <= 0) return r;
        off += (size_t)r;
    }
    return (ssize_t)off;
}

// Ensure we write all bytes
static ssize_t write_all(int fd, const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, (const uint8_t*)buf + off, n - off);
        if (w <= 0) return w;
        off += (size_t)w;
    }
    return (ssize_t)off;
}

// AES-256-GCM encrypt: produces iv (12B), tag (16B), ciphertext (pt_len)
static int aes_gcm_encrypt(const uint8_t *key32, const uint8_t *pt, int pt_len,
                           uint8_t iv[IV_LEN], uint8_t *ct, uint8_t tag[TAG_LEN]) {
    if (RAND_bytes(iv, IV_LEN) != 1) return 0;

    int outlen = 0, tmplen = 0, ok = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) break;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key32, iv) != 1) break;

        if (EVP_EncryptUpdate(ctx, ct, &outlen, pt, pt_len) != 1) break;

        if (EVP_EncryptFinal_ex(ctx, ct + outlen, &tmplen) != 1) break; // GCM final does not output more, but call anyway
        outlen += tmplen;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) break;

        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? outlen : 0;
}

// AES-256-GCM decrypt: needs iv (12B), tag (16B)
static int aes_gcm_decrypt(const uint8_t *key32, const uint8_t *ct, int ct_len,
                           const uint8_t iv[IV_LEN], const uint8_t tag[TAG_LEN],
                           uint8_t *pt) {
    int outlen = 0, tmplen = 0, ok = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key32, iv) != 1) break;

        if (EVP_DecryptUpdate(ctx, pt, &outlen, ct, ct_len) != 1) break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) break;

        if (EVP_DecryptFinal_ex(ctx, pt + outlen, &tmplen) != 1) { // auth fails -> 0
            ok = 0; break;
        }
        outlen += tmplen;
        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? outlen : 0;
}

// Frame: [uint32_t len][IV (12)][TAG (16)][CT (len-28)]
static int send_encrypted(int fd, const uint8_t key[32], const uint8_t *msg, uint32_t msg_len, double *enc_us_out) {
    uint8_t iv[IV_LEN], tag[TAG_LEN];
    uint8_t *ct = (uint8_t*)malloc(msg_len);
    if (!ct) return 0;

    struct timespec s, e;
    clock_gettime(CLOCK_MONOTONIC, &s);
    int ct_len = aes_gcm_encrypt(key, msg, (int)msg_len, iv, ct, tag);
    clock_gettime(CLOCK_MONOTONIC, &e);
    if (enc_us_out) *enc_us_out = elapsed_time_us(s, e);

    if (ct_len <= 0) { free(ct); return 0; }

    uint32_t payload_len = IV_LEN + TAG_LEN + (uint32_t)ct_len;
    uint32_t nlen = htonl(payload_len);

    int ok = write_all(fd, &nlen, sizeof(nlen)) > 0 &&
             write_all(fd, iv, IV_LEN) > 0 &&
             write_all(fd, tag, TAG_LEN) > 0 &&
             write_all(fd, ct, ct_len) > 0;

    free(ct);
    return ok;
}

static int recv_encrypted(int fd, const uint8_t key[32], uint8_t **msg_out, uint32_t *msg_len_out, double *dec_us_out) {
    uint32_t nlen = 0;
    if (read_exact(fd, &nlen, sizeof(nlen)) <= 0) return 0;
    uint32_t payload_len = ntohl(nlen);
    if (payload_len < IV_LEN + TAG_LEN || payload_len > 16*1024*1024) return 0;

    uint8_t iv[IV_LEN], tag[TAG_LEN];
    uint32_t ct_len = payload_len - IV_LEN - TAG_LEN;
    uint8_t *ct = (uint8_t*)malloc(ct_len);
    if (!ct) return 0;

    if (read_exact(fd, iv, IV_LEN) <= 0 || read_exact(fd, tag, TAG_LEN) <= 0 || read_exact(fd, ct, ct_len) <= 0) {
        free(ct); return 0;
    }

    uint8_t *pt = (uint8_t*)malloc(ct_len + 1);
    if (!pt) { free(ct); return 0; }

    struct timespec s, e;
    clock_gettime(CLOCK_MONOTONIC, &s);
    int pt_len = aes_gcm_decrypt(key, ct, (int)ct_len, iv, tag, pt);
    clock_gettime(CLOCK_MONOTONIC, &e);
    if (dec_us_out) *dec_us_out = elapsed_time_us(s, e);

    free(ct);
    if (pt_len <= 0) { free(pt); return 0; }

    pt[pt_len] = '\0';
    *msg_out = pt;
    *msg_len_out = (uint32_t)pt_len;
    return 1;
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    struct timespec ts1, ts2;

    // 1) Socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind"); exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 1) < 0) { perror("listen"); exit(EXIT_FAILURE); }
    printf("Server listening on port %d\n", PORT);

    client_fd = accept(server_fd, (struct sockaddr *)&address, &addr_len);
    if (client_fd < 0) { perror("accept"); exit(EXIT_FAILURE); }
    printf("Client connected\n");

    // 2) PQC: Init KEM
    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    if (!kem) { fprintf(stderr, "KEM init failed\n"); exit(EXIT_FAILURE); }

    uint8_t *server_pk = malloc(kem->length_public_key);
    uint8_t *server_sk = malloc(kem->length_secret_key);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    if (!server_pk || !server_sk || !shared_secret || !ciphertext) {
        fprintf(stderr, "malloc failed\n"); exit(EXIT_FAILURE);
    }

    // Keypair benchmark
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    if (OQS_KEM_keypair(kem, server_pk, server_sk) != OQS_SUCCESS) {
        fprintf(stderr, "server keypair failed\n"); exit(EXIT_FAILURE);
    }
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    printf("⏱ Keypair generation time: %.2f µs\n", elapsed_time_us(ts1, ts2));

    // 3) Receive client public key
    uint8_t *client_pk = malloc(kem->length_public_key);
    if (!client_pk) { fprintf(stderr, "malloc failed\n"); exit(EXIT_FAILURE); }
    if (read_exact(client_fd, client_pk, kem->length_public_key) <= 0) {
        fprintf(stderr, "failed to read client_pk\n"); exit(EXIT_FAILURE);
    }

    // 4) Encapsulate to client pk
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, client_pk) != OQS_SUCCESS) {
        fprintf(stderr, "encaps failed\n"); exit(EXIT_FAILURE);
    }
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    printf("⏱ Encapsulation time: %.2f µs\n", elapsed_time_us(ts1, ts2));

    // 5) Send ciphertext to client
    if (write_all(client_fd, ciphertext, kem->length_ciphertext) <= 0) {
        fprintf(stderr, "failed to send ciphertext\n"); exit(EXIT_FAILURE);
    }

    printf("✅ PQC shared secret established (AES-256-GCM session)\n");

    // 6) Chat loop
    while (1) {
        // Receive encrypted
        uint8_t *msg = NULL;
        uint32_t msg_len = 0;
        double dec_us = 0.0;

        if (!recv_encrypted(client_fd, shared_secret, &msg, &msg_len, &dec_us)) {
            printf("Client disconnected or decryption/auth failed\n");
            break;
        }
        printf("⏱ Message decryption+auth time: %.2f µs\n", dec_us);
        printf("Client: %s\n", msg);
        free(msg);

        // Prepare reply
        char outbuf[BUFFER_SIZE];
        printf("Server: ");
        fflush(stdout);
        if (!fgets(outbuf, sizeof(outbuf), stdin)) break;
        size_t send_len = strcspn(outbuf, "\n");
        outbuf[send_len] = '\0';

        double enc_us = 0.0;
        if (!send_encrypted(client_fd, shared_secret, (uint8_t*)outbuf, (uint32_t)send_len, &enc_us)) {
            fprintf(stderr, "send_encrypted failed\n"); break;
        }
        printf("⏱ Message encryption time: %.2f µs\n", enc_us);
    }

    free(client_pk); free(server_pk); free(server_sk); free(shared_secret); free(ciphertext);
    OQS_KEM_free(kem);
    close(client_fd); close(server_fd);
    return 0;
}
