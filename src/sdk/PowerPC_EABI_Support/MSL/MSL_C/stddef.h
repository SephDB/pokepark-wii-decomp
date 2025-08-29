#ifndef _STDDEF_H
#define _STDDEF_H

#include "MSL_Common/intptr_def.h" /* IWYU pragma: export */
#include "MSL_Common/null_def.h" /* IWYU pragma: export */
#include "MSL_Common/size_def.h" /* IWYU pragma: export */

#ifdef __cplusplus
extern "C" {
#endif

#define offsetof(ST, M) ((size_t) & (((ST *)0)->M))

#ifndef __cplusplus
typedef unsigned short wchar_t;
#endif

typedef wchar_t wint_t;

typedef void (*funcptr_t)(void);


#ifdef __cplusplus
}
#endif

#endif
