#include <Windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <wincrypt.h>
#include <iostream>
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")


// charToWChar: ANSI to wide string conversion
std::wstring charToWChar(const char* str) {
    int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    if (len <= 0) return L"";
    std::wstring wstr(len - 1, 0); // len includes null terminator, exclude it
    MultiByteToWideChar(CP_ACP, 0, str, -1, &wstr[0], len);
    return wstr;
}

bool IsFileSigned(const char* filePath) {
    // �� char* ת��Ϊ wchar_t*
    std::wstring wFilePath = charToWChar(filePath);

    // ���� WINTRUST_FILE_INFO �ṹ
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wFilePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    // ���� WINTRUST_DATA �ṹ
    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(trustData);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwUIContext = 0;
    trustData.pFile = &fileInfo;

    // ʹ�� Authenticode ���Ա�ʶ��
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // ���� WinVerifyTrust
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    // �ͷ�״̬
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return status == ERROR_SUCCESS;
}

// ============================================================
// Get the signer name from a signed file
// Returns empty string if unsigned or on error
// ============================================================
std::string GetSignerName(const char* filePath) {
    std::wstring wFilePath = charToWChar(filePath);

    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    std::string signerName;

    // Get the message handle from the signed file
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wFilePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0,
            NULL, NULL, NULL, &hStore, &hMsg, NULL)) {
        return "";
    }

    // Get signer info size
    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize)) {
        CryptMsgClose(hMsg);
        CertCloseStore(hStore, 0);
        return "";
    }

    // Allocate and get signer info
    std::vector<BYTE> signerInfoBuf(signerInfoSize);
    auto* signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(signerInfoBuf.data());
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo, &signerInfoSize)) {
        CryptMsgClose(hMsg);
        CertCloseStore(hStore, 0);
        return "";
    }

    // Find the signer certificate
    CERT_INFO certInfo = {};
    certInfo.Issuer = signerInfo->Issuer;
    certInfo.SerialNumber = signerInfo->SerialNumber;

    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SUBJECT_CERT, &certInfo, NULL);

    if (pCertContext) {
        // Get subject name
        char nameBuffer[256] = {};
        CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                          0, NULL, nameBuffer, sizeof(nameBuffer));
        signerName = nameBuffer;
        CertFreeCertificateContext(pCertContext);
    }

    CryptMsgClose(hMsg);
    CertCloseStore(hStore, 0);
    return signerName;
}

// ============================================================
// Check if a file is signed by Microsoft
// ============================================================
bool IsMicrosoftSigned(const char* filePath) {
    std::string signer = GetSignerName(filePath);
    if (signer.empty()) return false;

    // Convert to lowercase for comparison
    std::string lower = signer;
    for (auto& c : lower) c = (char)tolower(c);

    return lower.find("microsoft") != std::string::npos;
}

