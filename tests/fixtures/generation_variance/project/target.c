/*
 * Amalgamated from /home/luchitong/work/mini_parser/parser.h and parser.c.
 * This keeps the harness-generation pipeline on its single-target.c boundary
 * while using mini_parser as the only checked-in benchmark target.
 */
#ifndef MINI_PARSER_H
#define MINI_PARSER_H

#include <stddef.h>
#include <stdint.h>

/* Educational target: intentionally unsafe; never use for real input parsing. */
enum { MP_HEADER_SIZE = 8, MP_MAX_PAYLOAD = 64 };
enum mp_opcode {
    MP_READ = 1, MP_WRITE, MP_MULTIPLY, MP_STORE, MP_RELEASE, MP_USE,
    MP_NESTED_LENGTH
};
typedef struct {
    uint8_t *saved;
    size_t saved_len;
    int owns_saved;
    volatile uint32_t observation;
} mp_context;

void mp_init(mp_context *ctx);
void mp_destroy(mp_context *ctx);
uint16_t mp_checksum(const uint8_t *payload, size_t size);
/* One complete frame per call; a context can process multiple frames. */
int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);

#endif

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

void mp_init(mp_context *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

void mp_destroy(mp_context *ctx) {
    if (ctx->owns_saved) free(ctx->saved);
    mp_init(ctx);
}

uint16_t mp_checksum(const uint8_t *payload, size_t size) {
    uint16_t sum = 0;
    for (size_t i = 0; i < size; ++i) sum = (uint16_t)(sum + payload[i]);
    return sum;
}

int mp_parse(mp_context *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size < MP_HEADER_SIZE) return -1;
    if (data[0] != 'M' || data[1] != 'P' || data[2] != 1) return -2;
    size_t len = le16(data + 4);
    if (len > MP_MAX_PAYLOAD || len != size - MP_HEADER_SIZE) return -3;
    if (mp_checksum(data + MP_HEADER_SIZE, len) != le16(data + 6)) return -4;

    /* Exact allocation makes logical payload overreads observable with ASan,
       even when the harness input buffer has spare capacity. */
    uint8_t *p = (uint8_t *)malloc(len ? len : 1);
    if (!p) return -5;
    memcpy(p, data + MP_HEADER_SIZE, len);
    switch (data[3]) {
    case MP_READ:
        if (len >= 1) {
            size_t index = p[0];
            /* BUG 1: <= instead of < allows a one-past-end read. */
            if (index <= len) ctx->observation = p[index];
        }
        break;
    case MP_WRITE: {
        volatile uint8_t dst[16] = {0};
        /* BUG 2: payload length is not bounded by destination capacity. */
        for (size_t i = 0; i < len; ++i) dst[i] = p[i];
        ctx->observation = dst[0];
        break;
    }
    case MP_MULTIPLY:
        if (len >= 4) {
            uint32_t raw = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            if (raw <= INT32_MAX) {
                int32_t count = (int32_t)raw;
                /* BUG 3: signed multiplication can overflow before any
                   allocation. UBSan reports this without needing huge RAM. */
                ctx->observation = (uint32_t)(count * 16);
            }
        }
        break;
    case MP_STORE:
        if (len) {
            if (ctx->owns_saved) free(ctx->saved);
            ctx->saved = p;
            ctx->saved_len = len;
            ctx->owns_saved = 1;
            return 0; /* Transfer ownership to the context. */
        }
        break;
    case MP_RELEASE:
        if (ctx->owns_saved) {
            free(ctx->saved);
            ctx->owns_saved = 0;
            /* BUG 4: saved and saved_len remain valid-looking stale state. */
        }
        break;
    case MP_USE:
        if (ctx->saved && ctx->saved_len) ctx->observation = ctx->saved[0];
        break;
    case MP_NESTED_LENGTH:
        if (len >= 2) {
            size_t inner_len = le16(p);
            volatile uint8_t dst[32] = {0};
            /* BUG 5: checks destination capacity but not inner_len <= len-2.
               This length-validation defect manifests as a heap OOB read. */
            if (inner_len <= sizeof(dst)) {
                for (size_t i = 0; i < inner_len; ++i) dst[i] = p[2 + i];
                ctx->observation = dst[0];
            }
        }
        break;
    default:
        free(p);
        return -6;
    }
    free(p);
    return 0;
}
