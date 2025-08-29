// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SERVER_IP "127.0.0.1"
#define PORT 5555
#define KEM_ALG "ML-KEM-768"
#define BUFFER_SIZE 4096

#define IV_LEN 12
#define TAG_LEN 16

static double elapsed_ms(clock_t s, clock_t e) {
    return ((double)(e - s) / CLOCKS_PER_SEC) * 1000.0;
}

static double elapsed_us(struct timespec s, struct timespec e) {
    return (e.tv_sec - s.tv_sec) * 1e6 + (e.tv_nsec - s.tv_nsec) / 1e3;
}

static ssize_t read_exact(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (uint8_t*)buf + off, n - off);
        if (r <= 0) return r;
        off += (size_t)r;
    }
    return (ssize_t)off;
}

static ssize_t write_all(int fd, const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, (const uint8_t*)buf + off, n - off);
        if (w <= 0) return w;
        off += (size_t)w;
    }
    return (ssize_t)off;
}

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

        if (EVP_EncryptFinal_ex(ctx, ct + outlen, &tmplen) != 1) break;
        outlen += tmplen;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) break;

        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? outlen : 0;
}

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

        if (EVP_DecryptFinal_ex(ctx, pt + outlen, &tmplen) != 1) {
            ok = 0; break;
        }
        outlen += tmplen;
        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? outlen : 0;
}

// Frame: [uint32_t len][IV (12)][TAG (16)][CT]
static int send_encrypted(int fd, const uint8_t key[32], const uint8_t *msg, uint32_t msg_len, double *enc_us_out) {
    uint8_t iv[IV_LEN], tag[TAG_LEN];
    uint8_t *ct = (uint8_t*)malloc(msg_len);
    if (!ct) return 0;

    struct timespec s, e;
    clock_gettime(CLOCK_MONOTONIC, &s);
    int ct_len = aes_gcm_encrypt(key, msg, (int)msg_len, iv, ct, tag);
    clock_gettime(CLOCK_MONOTONIC, &e);
    if (enc_us_out) *enc_us_out = elapsed_us(s, e);

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
    if (dec_us_out) *dec_us_out = elapsed_us(s, e);

    free(ct);
    if (pt_len <= 0) { free(pt); return 0; }

    pt[pt_len] = '\0';
    *msg_out = pt;
    *msg_len_out = (uint32_t)pt_len;
    return 1;
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;

    // 1) Socket + connect
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { perror("socket"); return -1; }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) { perror("inet_pton"); return -1; }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { perror("connect"); return -1; }
    printf("Connected to server\n");

    // 2) PQC init
    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    if (!kem) { fprintf(stderr, "KEM init failed\n"); return -1; }

    uint8_t *client_pk = malloc(kem->length_public_key);
    uint8_t *client_sk = malloc(kem->length_secret_key);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    if (!client_pk || !client_sk || !shared_secret || !ciphertext) {
        fprintf(stderr, "malloc failed\n"); return -1;
    }

    // 3) Keypair + send public key
    clock_t cstart = clock();
    if (OQS_KEM_keypair(kem, client_pk, client_sk) != OQS_SUCCESS) {
        fprintf(stderr, "client keypair failed\n"); return -1;
    }
    clock_t cend = clock();
    printf("⏱ Keypair generation: %.4f ms\n", elapsed_ms(cstart, cend));

    if (write_all(sock, client_pk, kem->length_public_key) <= 0) {
        fprintf(stderr, "failed to send client_pk\n"); return -1;
    }

    // 4) Receive ciphertext and decapsulate
    if (read_exact(sock, ciphertext, kem->length_ciphertext) <= 0) {
        fprintf(stderr, "failed to receive ciphertext\n"); return -1;
    }

    cstart = clock();
    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, client_sk) != OQS_SUCCESS) {
        fprintf(stderr, "decaps failed\n"); return -1;
    }
    cend = clock();
    printf("⏱ Decapsulation: %.4f ms\n", elapsed_ms(cstart, cend));

    printf("✅ PQC shared secret established (AES-256-GCM session)\n");

    // 5) Chat loop
    while (1) {
        // Send
        char outbuf[BUFFER_SIZE];
        printf("Client: ");
        fflush(stdout);
        if (!fgets(outbuf, sizeof(outbuf), stdin)) break;
        size_t send_len = strcspn(outbuf, "\n");
        outbuf[send_len] = '\0';

        double enc_us = 0.0;
        if (!send_encrypted(sock, shared_secret, (uint8_t*)outbuf, (uint32_t)send_len, &enc_us)) {
            fprintf(stderr, "send_encrypted failed\n"); break;
        }
        printf("⏱ Message encryption time: %.2f µs\n", enc_us);

        // Receive
        uint8_t *msg = NULL;
        uint32_t msg_len = 0;
        double dec_us = 0.0;
        if (!recv_encrypted(sock, shared_secret, &msg, &msg_len, &dec_us)) {
            printf("Server disconnected or decryption/auth failed\n");
            break;
        }
        printf("⏱ Message decryption+auth time: %.2f µs\n", dec_us);
        printf("Server: %s\n", msg);
        free(msg);
    }

    free(client_pk); free(client_sk); free(shared_secret); free(ciphertext);
    OQS_KEM_free(kem);
    close(sock);
    return 0;
}