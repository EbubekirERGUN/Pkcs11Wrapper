#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

typedef uint8_t CK_BYTE;
typedef CK_BYTE CK_BBOOL;
typedef CK_BYTE CK_UTF8CHAR;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_USER_TYPE;
typedef unsigned long CK_MECHANISM_TYPE;

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef struct CK_FUNCTION_LIST_3_0 CK_FUNCTION_LIST_3_0;
typedef struct CK_INTERFACE CK_INTERFACE;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    void* pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef struct CK_INTERFACE {
    CK_UTF8CHAR* pInterfaceName;
    void* pFunctionList;
    CK_FLAGS flags;
} CK_INTERFACE;

struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_RV (*C_Initialize)(void* pInitArgs);
    CK_RV (*C_Finalize)(void* pReserved);
    void* C_GetInfo;
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST** ppFunctionList);
    void* C_GetSlotList;
    void* C_GetSlotInfo;
    void* C_GetTokenInfo;
    void* C_GetMechanismList;
    void* C_GetMechanismInfo;
    void* C_InitToken;
    void* C_InitPIN;
    void* C_SetPIN;
    CK_RV (*C_OpenSession)(CK_SLOT_ID slotId, CK_FLAGS flags, void* pApplication, void* notify, CK_SESSION_HANDLE* phSession);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE hSession);
    void* C_CloseAllSessions;
    void* C_GetSessionInfo;
    void* C_GetOperationState;
    void* C_SetOperationState;
    void* C_Login;
    void* C_Logout;
    void* C_CreateObject;
    void* C_CopyObject;
    void* C_DestroyObject;
    void* C_GetObjectSize;
    void* C_GetAttributeValue;
    void* C_SetAttributeValue;
    void* C_FindObjectsInit;
    void* C_FindObjects;
    void* C_FindObjectsFinal;
    void* C_EncryptInit;
    void* C_Encrypt;
    void* C_EncryptUpdate;
    void* C_EncryptFinal;
    void* C_DecryptInit;
    void* C_Decrypt;
    void* C_DecryptUpdate;
    void* C_DecryptFinal;
    void* C_DigestInit;
    void* C_Digest;
    void* C_DigestUpdate;
    void* C_DigestKey;
    void* C_DigestFinal;
    void* C_SignInit;
    void* C_Sign;
    void* C_SignUpdate;
    void* C_SignFinal;
    void* C_SignRecoverInit;
    void* C_SignRecover;
    void* C_VerifyInit;
    void* C_Verify;
    void* C_VerifyUpdate;
    void* C_VerifyFinal;
    void* C_VerifyRecoverInit;
    void* C_VerifyRecover;
    void* C_DigestEncryptUpdate;
    void* C_DecryptDigestUpdate;
    void* C_SignEncryptUpdate;
    void* C_DecryptVerifyUpdate;
    void* C_GenerateKey;
    void* C_GenerateKeyPair;
    void* C_WrapKey;
    void* C_UnwrapKey;
    void* C_DeriveKey;
    void* C_SeedRandom;
    void* C_GenerateRandom;
    void* C_GetFunctionStatus;
    void* C_CancelFunction;
    void* C_WaitForSlotEvent;
};

struct CK_FUNCTION_LIST_3_0 {
    CK_FUNCTION_LIST base;
    CK_RV (*C_GetInterfaceList)(CK_INTERFACE* pInterfaces, CK_ULONG* pulCount);
    CK_RV (*C_GetInterface)(CK_UTF8CHAR* pInterfaceName, CK_VERSION* pVersion, CK_INTERFACE** ppInterface, CK_FLAGS flags);
    CK_RV (*C_LoginUser)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR* pPin, CK_ULONG ulPinLen, CK_UTF8CHAR* pUsername, CK_ULONG ulUsernameLen);
    CK_RV (*C_SessionCancel)(CK_SESSION_HANDLE hSession, CK_FLAGS flags);
    CK_RV (*C_MessageEncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM* pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_EncryptMessage)(CK_SESSION_HANDLE hSession, void* pParameter, CK_ULONG ulParameterLen, CK_BYTE* pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE* pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE* pCiphertext, CK_ULONG* pulCiphertextLen);
    void* C_EncryptMessageBegin;
    void* C_EncryptMessageNext;
    CK_RV (*C_MessageEncryptFinal)(CK_SESSION_HANDLE hSession);
    void* C_MessageDecryptInit;
    void* C_DecryptMessage;
    void* C_DecryptMessageBegin;
    void* C_DecryptMessageNext;
    void* C_MessageDecryptFinal;
    void* C_MessageSignInit;
    void* C_SignMessage;
    void* C_SignMessageBegin;
    void* C_SignMessageNext;
    void* C_MessageSignFinal;
    void* C_MessageVerifyInit;
    void* C_VerifyMessage;
    void* C_VerifyMessageBegin;
    void* C_VerifyMessageNext;
    void* C_MessageVerifyFinal;
};

enum {
    CK_FALSE = 0,
    CK_TRUE = 1,
    MAX_SESSIONS = 32
};

static const CK_RV CKR_OK = 0x00000000UL;
static const CK_RV CKR_ARGUMENTS_BAD = 0x00000007UL;
static const CK_RV CKR_BUFFER_TOO_SMALL = 0x00000150UL;
static const CK_RV CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191UL;
static const CK_RV CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190UL;
static const CK_RV CKR_FUNCTION_NOT_SUPPORTED = 0x00000054UL;
static const CK_RV CKR_KEY_HANDLE_INVALID = 0x00000060UL;
static const CK_RV CKR_MECHANISM_INVALID = 0x00000070UL;
static const CK_RV CKR_MECHANISM_PARAM_INVALID = 0x00000071UL;
static const CK_RV CKR_OPERATION_NOT_INITIALIZED = 0x00000091UL;
static const CK_RV CKR_PIN_INCORRECT = 0x000000A0UL;
static const CK_RV CKR_SESSION_COUNT = 0x000000B1UL;
static const CK_RV CKR_SESSION_HANDLE_INVALID = 0x000000B3UL;
static const CK_RV CKR_USER_NOT_LOGGED_IN = 0x00000101UL;

static const CK_SLOT_ID SHIM_SLOT_ID = 1UL;
static const CK_OBJECT_HANDLE SHIM_KEY_HANDLE = 1UL;
static const CK_USER_TYPE SHIM_USER_TYPE = 1UL;
static const CK_MECHANISM_TYPE SHIM_MECHANISM_TYPE = 0x00001082UL;
static const CK_BYTE SHIM_MECHANISM_PARAMETER[] = { 0xCA, 0xFE, 0x01 };
static const CK_UTF8CHAR SHIM_PIN[] = "123456";
static const CK_UTF8CHAR SHIM_USERNAME[] = "runtime-user";
static const CK_UTF8CHAR SHIM_INTERFACE_NAME[] = "PKCS 11";

typedef struct shim_session_state {
    CK_BBOOL open;
    CK_BBOOL logged_in;
    CK_BBOOL encrypt_active;
} shim_session_state;

static CK_BBOOL g_initialized = CK_FALSE;
static shim_session_state g_sessions[MAX_SESSIONS];

static CK_RV shim_initialize(void* pInitArgs);
static CK_RV shim_finalize(void* pReserved);
static CK_RV shim_get_function_list(CK_FUNCTION_LIST** ppFunctionList);
static CK_RV shim_open_session(CK_SLOT_ID slotId, CK_FLAGS flags, void* pApplication, void* notify, CK_SESSION_HANDLE* phSession);
static CK_RV shim_close_session(CK_SESSION_HANDLE hSession);
static CK_RV shim_get_interface_list(CK_INTERFACE* pInterfaces, CK_ULONG* pulCount);
static CK_RV shim_get_interface(CK_UTF8CHAR* pInterfaceName, CK_VERSION* pVersion, CK_INTERFACE** ppInterface, CK_FLAGS flags);
static CK_RV shim_login_user(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR* pPin, CK_ULONG ulPinLen, CK_UTF8CHAR* pUsername, CK_ULONG ulUsernameLen);
static CK_RV shim_session_cancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags);
static CK_RV shim_message_encrypt_init(CK_SESSION_HANDLE hSession, CK_MECHANISM* pMechanism, CK_OBJECT_HANDLE hKey);
static CK_RV shim_encrypt_message(CK_SESSION_HANDLE hSession, void* pParameter, CK_ULONG ulParameterLen, CK_BYTE* pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE* pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE* pCiphertext, CK_ULONG* pulCiphertextLen);
static CK_RV shim_message_encrypt_final(CK_SESSION_HANDLE hSession);

static CK_INTERFACE g_interface = {
    (CK_UTF8CHAR*)SHIM_INTERFACE_NAME,
    NULL,
    0UL
};

static CK_FUNCTION_LIST_3_0 g_function_list_30 = {
    .base = {
        .version = { 3, 0 },
        .C_Initialize = shim_initialize,
        .C_Finalize = shim_finalize,
        .C_GetFunctionList = shim_get_function_list,
        .C_OpenSession = shim_open_session,
        .C_CloseSession = shim_close_session
    },
    .C_GetInterfaceList = shim_get_interface_list,
    .C_GetInterface = shim_get_interface,
    .C_LoginUser = shim_login_user,
    .C_SessionCancel = shim_session_cancel,
    .C_MessageEncryptInit = shim_message_encrypt_init,
    .C_EncryptMessage = shim_encrypt_message,
    .C_MessageEncryptFinal = shim_message_encrypt_final
};

static shim_session_state* get_session(CK_SESSION_HANDLE hSession)
{
    if (hSession == 0 || hSession > MAX_SESSIONS) {
        return NULL;
    }

    shim_session_state* session = &g_sessions[hSession - 1];
    if (session->open == CK_FALSE) {
        return NULL;
    }

    return session;
}

static CK_RV require_initialized(void)
{
    return g_initialized == CK_TRUE ? CKR_OK : CKR_CRYPTOKI_NOT_INITIALIZED;
}

static CK_RV shim_initialize(void* pInitArgs)
{
    (void)pInitArgs;

    if (g_initialized == CK_TRUE) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    memset(g_sessions, 0, sizeof(g_sessions));
    g_interface.pFunctionList = &g_function_list_30;
    g_initialized = CK_TRUE;
    return CKR_OK;
}

static CK_RV shim_finalize(void* pReserved)
{
    (void)pReserved;
    memset(g_sessions, 0, sizeof(g_sessions));
    g_initialized = CK_FALSE;
    return CKR_OK;
}

static CK_RV shim_get_function_list(CK_FUNCTION_LIST** ppFunctionList)
{
    if (ppFunctionList == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &g_function_list_30.base;
    return CKR_OK;
}

static CK_RV shim_open_session(CK_SLOT_ID slotId, CK_FLAGS flags, void* pApplication, void* notify, CK_SESSION_HANDLE* phSession)
{
    (void)flags;
    (void)pApplication;
    (void)notify;

    CK_RV init_result = require_initialized();
    if (init_result != CKR_OK) {
        return init_result;
    }

    if (slotId != SHIM_SLOT_ID || phSession == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    for (CK_ULONG i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].open == CK_FALSE) {
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].open = CK_TRUE;
            *phSession = i + 1;
            return CKR_OK;
        }
    }

    return CKR_SESSION_COUNT;
}

static CK_RV shim_close_session(CK_SESSION_HANDLE hSession)
{
    CK_RV init_result = require_initialized();
    if (init_result != CKR_OK) {
        return init_result;
    }

    shim_session_state* session = get_session(hSession);
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    memset(session, 0, sizeof(*session));
    return CKR_OK;
}

static CK_RV shim_get_interface_list(CK_INTERFACE* pInterfaces, CK_ULONG* pulCount)
{
    if (pulCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (pInterfaces == NULL) {
        *pulCount = 1;
        return CKR_OK;
    }

    if (*pulCount < 1) {
        *pulCount = 1;
        return CKR_BUFFER_TOO_SMALL;
    }

    pInterfaces[0] = g_interface;
    *pulCount = 1;
    return CKR_OK;
}

static CK_RV shim_get_interface(CK_UTF8CHAR* pInterfaceName, CK_VERSION* pVersion, CK_INTERFACE** ppInterface, CK_FLAGS flags)
{
    if (ppInterface == NULL || flags != 0UL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (pVersion != NULL && (pVersion->major != 3 || pVersion->minor != 0)) {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    if (pInterfaceName != NULL && strcmp((const char*)pInterfaceName, (const char*)SHIM_INTERFACE_NAME) != 0) {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    *ppInterface = &g_interface;
    return CKR_OK;
}

static CK_RV shim_login_user(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR* pPin, CK_ULONG ulPinLen, CK_UTF8CHAR* pUsername, CK_ULONG ulUsernameLen)
{
    CK_RV init_result = require_initialized();
    if (init_result != CKR_OK) {
        return init_result;
    }

    shim_session_state* session = get_session(hSession);
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (userType != SHIM_USER_TYPE) {
        return CKR_ARGUMENTS_BAD;
    }

    if (pPin == NULL || ulPinLen != (sizeof(SHIM_PIN) - 1) || memcmp(pPin, SHIM_PIN, sizeof(SHIM_PIN) - 1) != 0) {
        return CKR_PIN_INCORRECT;
    }

    if (pUsername == NULL || ulUsernameLen != (sizeof(SHIM_USERNAME) - 1) || memcmp(pUsername, SHIM_USERNAME, sizeof(SHIM_USERNAME) - 1) != 0) {
        return CKR_ARGUMENTS_BAD;
    }

    session->logged_in = CK_TRUE;
    return CKR_OK;
}

static CK_RV shim_session_cancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
    (void)flags;

    CK_RV init_result = require_initialized();
    if (init_result != CKR_OK) {
        return init_result;
    }

    shim_session_state* session = get_session(hSession);
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    session->encrypt_active = CK_FALSE;
    return CKR_OK;
}

static CK_RV shim_message_encrypt_init(CK_SESSION_HANDLE hSession, CK_MECHANISM* pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV init_result = require_initialized();
    if (init_result != CKR_OK) {
        return init_result;
    }

    shim_session_state* session = get_session(hSession);
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (session->logged_in == CK_FALSE) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    if (hKey != SHIM_KEY_HANDLE) {
        return CKR_KEY_HANDLE_INVALID;
    }

    if (pMechanism == NULL || pMechanism->mechanism != SHIM_MECHANISM_TYPE) {
        return CKR_MECHANISM_INVALID;
    }

    if (pMechanism->pParameter == NULL ||
        pMechanism->ulParameterLen != sizeof(SHIM_MECHANISM_PARAMETER) ||
        memcmp(pMechanism->pParameter, SHIM_MECHANISM_PARAMETER, sizeof(SHIM_MECHANISM_PARAMETER)) != 0) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    session->encrypt_active = CK_TRUE;
    return CKR_OK;
}

static CK_RV shim_encrypt_message(CK_SESSION_HANDLE hSession, void* pParameter, CK_ULONG ulParameterLen, CK_BYTE* pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE* pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE* pCiphertext, CK_ULONG* pulCiphertextLen)
{
    CK_RV init_result = require_initialized();
    if (init_result != CKR_OK) {
        return init_result;
    }

    shim_session_state* session = get_session(hSession);
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (session->logged_in == CK_FALSE) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    if (session->encrypt_active == CK_FALSE) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    if (pulCiphertextLen == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((ulParameterLen > 0 && pParameter == NULL) ||
        (ulAssociatedDataLen > 0 && pAssociatedData == NULL) ||
        (ulPlaintextLen > 0 && pPlaintext == NULL)) {
        return CKR_ARGUMENTS_BAD;
    }

    CK_ULONG required = ulParameterLen + ulAssociatedDataLen + ulPlaintextLen;
    if (pCiphertext == NULL) {
        *pulCiphertextLen = required;
        return CKR_OK;
    }

    if (*pulCiphertextLen < required) {
        *pulCiphertextLen = required;
        return CKR_BUFFER_TOO_SMALL;
    }

    CK_BYTE* cursor = pCiphertext;
    if (ulParameterLen > 0) {
        memcpy(cursor, pParameter, ulParameterLen);
        cursor += ulParameterLen;
    }

    if (ulAssociatedDataLen > 0) {
        memcpy(cursor, pAssociatedData, ulAssociatedDataLen);
        cursor += ulAssociatedDataLen;
    }

    for (CK_ULONG i = 0; i < ulPlaintextLen; i++) {
        cursor[i] = (CK_BYTE)(pPlaintext[i] ^ 0x5AU);
    }

    *pulCiphertextLen = required;
    return CKR_OK;
}

static CK_RV shim_message_encrypt_final(CK_SESSION_HANDLE hSession)
{
    CK_RV init_result = require_initialized();
    if (init_result != CKR_OK) {
        return init_result;
    }

    shim_session_state* session = get_session(hSession);
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    session->encrypt_active = CK_FALSE;
    return CKR_OK;
}

EXPORT CK_RV C_GetFunctionList(CK_FUNCTION_LIST** ppFunctionList)
{
    return shim_get_function_list(ppFunctionList);
}

EXPORT CK_RV C_GetInterfaceList(CK_INTERFACE* pInterfaces, CK_ULONG* pulCount)
{
    return shim_get_interface_list(pInterfaces, pulCount);
}

EXPORT CK_RV C_GetInterface(CK_UTF8CHAR* pInterfaceName, CK_VERSION* pVersion, CK_INTERFACE** ppInterface, CK_FLAGS flags)
{
    return shim_get_interface(pInterfaceName, pVersion, ppInterface, flags);
}
