#include "Cipher.hpp"

using namespace std;

const uint8_t Sbox1[16] = { 0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1};
const uint8_t Sbox2[16] = { 0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF};
const uint8_t Sbox3[16] = { 0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0};
const uint8_t Sbox4[16] = { 0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB};
const uint8_t Sbox5[16] = { 0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC};
const uint8_t Sbox6[16] = { 0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0};
const uint8_t Sbox7[16] = { 0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7};
const uint8_t Sbox8[16] = { 0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2};

const uint8_t KeySch[32] = {0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0};

const uint16_t initialVal[16] = {0x0102, 0x0304, 0x0506, 0x0708, 0x090A, 0x0B0C, 0x0D0E, 0x0F10, 0x1112, 0x1314, 0x1516, 0x1718, 0x191A, 0x1B1C, 0x1D1E, 0x1F20};

const uint16_t crcPoly = 0x1021;

inline hash256 sum256(hash256 first, hash256 second){
    hash256 ret;
    uint8_t carry = 0;
    for(uint8_t i = 0; i < 16; i++){
        uint32_t result = first.data[i] + second.data[i] + carry;
        ret.data[i] = result & 0xFFFF;
        carry = (result & 0x10000) >> 16;
    }
    return ret;
}

inline hash256 hashsbox(hash256 arg){
    for(uint8_t i = 0; i < 16; i++){
        uint8_t v1 = arg.data[i]&0xF, v2 = (arg.data[i] >> 4)&0xF, v3 = (arg.data[i] >> 8)&0xF, v4 = arg.data[i] >> 12;
        v1 = Sbox1[v1], v2 = Sbox2[v2], v3 = Sbox3[v3], v4 = Sbox4[v4];
        arg.data[i] = v4 | (v3 << 4) | (v2 << 8) | (v1 << 12); //!!mix!!
    }
    return arg;
}

inline hash256 rot7l(hash256 arg){
    uint16_t carry, lastcarry;
    uint32_t result;
    //rotate first
    result = (uint32_t)arg.data[15] << 7;
    lastcarry = (result&0xFFFF0000) >> 16;
    arg.data[15] = result&0x0000FFFF;
    for(int8_t i = 14; i >= 0; i--){
        result = (uint32_t)arg.data[i] << 7;
        carry = (result&0xFFFF0000) >> 16;
        arg.data[i] = result&0x0000FFFF;
        arg.data[i+1] |= carry;
    }
    arg.data[0] |= lastcarry;
    return arg;
}

hash256 HashRound(hash256 val, hash256 prev){
    hash256 ret = sum256(val, prev);
    ret = hashsbox(ret);
    ret = rot7l(ret);
    return ret;
}

hash256 HashFunc(const char* key, int len){
    char intkey[1024];
    for(uint16_t i = 0; i < 1024; i+=len){
        if( (1024 - i) >= len)
            for(uint8_t j = 0; j < len; j++)
                intkey[i+j] = key[j];
        else for(uint16_t j = i; j < 1024; j++)
            intkey[j] = 0;
    }
    //ready to process
    hash256 ret( {0x0102, 0x0304, 0x0506, 0x0708, 0x090A, 0x0B0C, 0x0D0E, 0x0F10, 0x1112, 0x1314, 0x1516, 0x1718, 0x191A, 0x1B1C, 0x1D1E, 0x1F20} );
    for(uint16_t i = 0; i < 1024; i+=32){
        hash256 cur;
        memcpy(cur.data, intkey+i, 32);
        ret = HashRound(cur, ret);
    }
    return ret;
}

inline uint32_t rot11l(uint32_t val){
    uint64_t result = (uint64_t)(val) << 11;
    uint32_t ret = (result&0xFFFFFFFF) | (result >> 32);
    return ret;
}

inline uint32_t sum32(uint32_t val1, uint32_t val2){
    uint64_t result = val1 + val2;
    uint32_t ret = result&0xFFFFFFFF;
    return ret;
}

inline uint32_t ciphsbox(uint32_t val){
    uint8_t v[8];
    uint32_t ret = 0;
    for(uint8_t i = 0; i < 8; i++) v[i] = (val >> i*4)&0xF;
    v[0] = Sbox1[v[0]]; v[1] = Sbox2[v[1]];
    v[2] = Sbox3[v[2]]; v[3] = Sbox4[v[3]];
    v[4] = Sbox5[v[4]]; v[5] = Sbox6[v[5]];
    v[6] = Sbox7[v[6]]; v[7] = Sbox8[v[7]];
    for(uint8_t i = 0; i < 8; i++) ret |= (uint32_t)v[i] << i*4;
    return ret;
}

inline uint32_t gostf(uint32_t a, uint32_t k){
    uint32_t ret = sum32(a, k);
    ret = ciphsbox(ret);
    ret = rot11l(ret);
    return ret;
}

void CipherRound(uint32_t &l, uint32_t &r, uint32_t key){
    uint32_t pl = l;
    l = r ^ gostf(l, key);
    r = pl;
}

uint64_t CipherFunc(uint64_t data, hash256 key, bool way ){
    uint32_t keys[8];
    memcpy(keys, key.data, 32);
    uint32_t l = data&0xFFFFFFFF, r = data >> 32;
    for(uint8_t i = 0; i < 32; i++){
        uint8_t index = way ? i : (31 - i);
        uint32_t curkey = keys[KeySch[index]];
        CipherRound(l, r, curkey);
    }
    uint64_t ret = (uint64_t)r | ((uint64_t)l << 32);
    return ret;
}

uint16_t crc16(uint8_t* data, uint8_t len){
    uint32_t rem = 0;
    for(uint8_t i = 0; i < len; i++){
        rem ^= (uint16_t)data[i] << 8;
        for(uint8_t j = 0; j < 8; j++){
            if(rem&0x8000) rem = (rem << 1) ^ crcPoly;
            else rem <<= 1;
            rem &= 0xFFFF;
        }
    }
    return rem;
}
