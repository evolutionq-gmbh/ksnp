/**
 * @file compat.h
 * @copyright Copyright 2025 evolutionQ GmbH. Licensed under the BSD-3-Clause
 * license, see LICENSE.
 *
 * @brief Macros to help with compatibility between various C++ and C dialects.
 *
 * This file should be included twice, once to define the helper macros, and
 * once again to undefine them.
 */

#ifndef COMPAT_ENTER

#define COMPAT_ENTER

#if defined(__cplusplus) && __cplusplus >= 201103L
#if __cplusplus >= 201703L
#define NODISCARD [[nodiscard]]
#endif
#define NOEXCEPT noexcept
#define ENUM_TYPE(ident, type) enum class ident : type
#define ENUM_TYPE_T(ident, type)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#define ENUM_TYPE(ident, type) enum ident : type
#define ENUM_TYPE_T(ident, type) typedef enum ident ident
#else
#define ENUM_TYPE(ident, type) enum ident
#define ENUM_TYPE_T(ident, type) typedef type ident
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NODISCARD
#define NODISCARD
#endif
#ifndef NOEXCEPT
#define NOEXCEPT
#endif

#else  // COMPAT_ENTER

#undef COMPAT_ENTER
#undef NODISCARD
#undef NOEXCEPT
#undef ENUM_TYPE

#ifdef __cplusplus
}
#endif

#endif  // COMPAT_ENTER
