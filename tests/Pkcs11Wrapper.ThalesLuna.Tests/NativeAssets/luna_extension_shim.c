#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

typedef uint8_t CK_BYTE;
typedef unsigned long CK_RV;

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef struct LUNA_FUNCTION_LIST_HEADER LUNA_FUNCTION_LIST_HEADER;

struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_RV (*C_Initialize)(void* pInitArgs);
    CK_RV (*C_Finalize)(void* pReserved);
    void* C_GetInfo;
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST** ppFunctionList);
};

struct LUNA_FUNCTION_LIST_HEADER {
    CK_VERSION version;
};

static const CK_RV CKR_OK = 0x00000000UL;
static const CK_RV CKR_ARGUMENTS_BAD = 0x00000007UL;
static const CK_RV CKR_FUNCTION_NOT_SUPPORTED = 0x00000054UL;

static CK_RV shim_initialize(void* pInitArgs);
static CK_RV shim_finalize(void* pReserved);
static CK_RV shim_get_function_list(CK_FUNCTION_LIST** ppFunctionList);
static CK_RV shim_ca_get_function_list(LUNA_FUNCTION_LIST_HEADER** ppFunctionList);

static CK_FUNCTION_LIST g_function_list = {
    .version = { 3, 0 },
    .C_Initialize = shim_initialize,
    .C_Finalize = shim_finalize,
    .C_GetFunctionList = shim_get_function_list
};

static LUNA_FUNCTION_LIST_HEADER g_luna_function_list = {
    .version = { 1, 0 }
};

static const char* get_mode(void)
{
#if defined(LUNA_SHIM_STATIC_MODE_UNSUPPORTED)
    return "unsupported";
#elif defined(LUNA_SHIM_STATIC_MODE_NULL_POINTER)
    return "null-pointer";
#else
    const char* mode = getenv("PKCS11_LUNA_SHIM_MODE");
    return mode == NULL ? "available" : mode;
#endif
}

static CK_RV shim_initialize(void* pInitArgs)
{
    (void)pInitArgs;
    return CKR_OK;
}

static CK_RV shim_finalize(void* pReserved)
{
    (void)pReserved;
    return CKR_OK;
}

static CK_RV shim_get_function_list(CK_FUNCTION_LIST** ppFunctionList)
{
    if (ppFunctionList == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &g_function_list;
    return CKR_OK;
}

static CK_RV shim_ca_get_function_list(LUNA_FUNCTION_LIST_HEADER** ppFunctionList)
{
    const char* mode = get_mode();

    if (strcmp(mode, "unsupported") == 0) {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    if (ppFunctionList == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (strcmp(mode, "null-pointer") == 0) {
        *ppFunctionList = NULL;
        return CKR_OK;
    }

    *ppFunctionList = &g_luna_function_list;
    return CKR_OK;
}

EXPORT CK_RV C_GetFunctionList(CK_FUNCTION_LIST** ppFunctionList)
{
    return shim_get_function_list(ppFunctionList);
}

EXPORT CK_RV CA_GetFunctionList(LUNA_FUNCTION_LIST_HEADER** ppFunctionList)
{
    return shim_ca_get_function_list(ppFunctionList);
}
