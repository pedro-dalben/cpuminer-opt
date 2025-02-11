#ifndef ALGO_AURUM_AURUM_H
#define ALGO_AURUM_AURUM_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

  int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);

#ifdef __cplusplus
}
#endif

#endif // ALGO_AURUM_AURUM_H
