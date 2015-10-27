#ifndef CIPHER_HPP
#define CIPHER_HPP

#include <cstdint>
#include <cstring>
#include <utility>

struct hash256{
    uint16_t data[16];
};

hash256 HashRound(hash256 val, hash256 prev);

hash256 HashFunc(const char* key, int len);

void CipherRound(uint32_t &l, uint32_t &r, uint32_t key);

uint64_t CipherFunc(uint64_t data, hash256 key, bool way = true);

uint16_t crc16(uint8_t* data, uint8_t len);

#endif // CIPHER_HPP
