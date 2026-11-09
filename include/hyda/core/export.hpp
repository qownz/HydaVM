#pragma once

#if defined(_WIN32)
#  define HYDA_ENTRY      extern "C" __declspec(dllexport)
#  define HYDA_ENTRY_DATA __declspec(dllexport)
#else
#  define HYDA_ENTRY      extern "C"
#  define HYDA_ENTRY_DATA
#endif

#if defined(_WIN32)
#  define HYDA_INTERNAL
#else
#  define HYDA_INTERNAL __attribute__((visibility("hidden")))
#endif
