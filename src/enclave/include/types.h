#ifndef _TYPES_H_
#define _TYPES_H_

#define BUF_NUM 2

#define MOD2(x) ((x) % BUF_NUM)

struct sealed_buf_t {
    unsigned int index;
    void* sealed_buf_ptr[BUF_NUM];
};

#endif
