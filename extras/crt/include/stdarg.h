// <ORIGINAL-AUTHOR>: Barak Nirenberg
// <COMPONENT>: libc
// <FILE-TYPE>: public header

#ifndef __STDARAG_H__
#define __STDARAG_H__

#ifdef  __cplusplus
extern "C" {
#endif

#if !defined(_W64)
#if !defined(__midl) && (defined(_X86_) || defined(_M_IX86))
#define _W64 __w64
#else
#define _W64
#endif
#endif

#ifndef _VA_LIST_DEFINED
typedef char *  va_list;
#define _VA_LIST_DEFINED
#endif
#ifndef __GNUC__
typedef va_list __va_list;
#endif

#ifdef  __cplusplus
#define _ADDRESSOF(v)   ( &reinterpret_cast<const char &>(v) )
#else
#define _ADDRESSOF(v)   ( &(v) )
#endif

#define _SLOTSIZEOF(t)  (sizeof(t))
#define _APALIGN(t,ap)  (__alignof(t))

#if   defined(_M_IX86)

#define _INTSIZEOF(n)   ( (sizeof(n) + sizeof(int) - 1) & ~(sizeof(int) - 1) )

#define _crt_va_start(ap,v)  ( ap = (va_list)_ADDRESSOF(v) + _INTSIZEOF(v) )
#define _crt_va_arg(ap,t)    ( *(t *)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)) )
#define _crt_va_end(ap)      ( ap = (va_list)0 )

#elif defined(_M_X64)


extern void __cdecl __va_start(va_list *, ...);

#define _crt_va_start(ap, x) ( __va_start(&ap, x) )
#define _crt_va_arg(ap, t)   \
    ( ( sizeof(t) > sizeof(__int64) || ( sizeof(t) & (sizeof(t) - 1) ) != 0 ) \
        ? **(t **)( ( ap += sizeof(__int64) ) - sizeof(__int64) ) \
        :  *(t  *)( ( ap += sizeof(__int64) ) - sizeof(__int64) ) )
#define _crt_va_end(ap)      ( ap = (va_list)0 )

#else

/* A guess at the proper definitions for other platforms */

#define _INTSIZEOF(n)   ( (sizeof(n) + sizeof(int) - 1) & ~(sizeof(int) - 1) )

#define _crt_va_start(ap,v)  ( ap = (va_list)_ADDRESSOF(v) + _INTSIZEOF(v) )
#define _crt_va_arg(ap,t)    ( *(t *)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)) )
#define _crt_va_end(ap)      ( ap = (va_list)0 )

#endif

#ifdef  __cplusplus
}
#endif

#define va_start _crt_va_start
#define va_end _crt_va_end
#define va_arg _crt_va_arg

#define va_copy(dest, src) (dest = src)

#endif //__STDARAG_H__
