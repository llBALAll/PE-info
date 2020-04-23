
#include <Windows.h>
#include <iostream>
#include <time.h>

#define BUILD_DLL

#ifdef BUILD_DLL
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllimport)
#endif



#ifdef __cplusplus
extern "C" {
#endif



#ifdef __cplusplus
}
#endif
