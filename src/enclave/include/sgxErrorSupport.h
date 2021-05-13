#ifndef _ERROR_SUPPORT_H
#define _ERROR_SUPPORT_H

#include "sgx_error.h"

#ifdef __cplusplus
extern "C" {
#endif

void sgxErrorReport(sgx_status_t ret);

#ifdef __cplusplus
}
#endif

#endif
