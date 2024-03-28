#include "pch.h"

#define PLUGIN_NAME		"OpenLumina"
#define PLUGIN_DESC		"Allows IDA to connect to third party Lumina servers"
#define PLUGIN_PREFIX	"OpenLumina: "

bool load_and_decode_certificate(bytevec_t& buffer, const char* certFilePath)
{
    auto certFile = fopenRT(certFilePath);

    if (certFile != nullptr)
    {
        qstring cert;
        qstring line;

        if (qgetline(&line, certFile) >= 0)
        {
            do
            {
                if (strcmp(line.c_str(), "-----BEGIN CERTIFICATE-----"))
                {
                    if (!strcmp(line.c_str(), "-----END CERTIFICATE-----"))
                        break;

                    if (line.length())
                        cert += line;
                }
            } while (qgetline(&line, certFile) >= 0);
        }

        qfclose(certFile);

        if ((debug & IDA_DEBUG_LUMINA) != 0)
            msg(PLUGIN_PREFIX "cert read: %s\n", cert.c_str());

        return base64_decode(&buffer, cert.c_str(), cert.length());
    }
    return false;
}

static plugin_ctx_t* s_plugin_ctx = nullptr;

static BOOL(WINAPI* TrueCertAddEncodedCertificateToStore)(HCERTSTORE hCertStore, DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded, DWORD dwAddDisposition, PCCERT_CONTEXT* ppCertContext) = CertAddEncodedCertificateToStore;

static BOOL WINAPI HookedCertAddEncodedCertificateToStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded, DWORD dwAddDisposition, PCCERT_CONTEXT* ppCertContext)
{
    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "HookedCertAddEncodedCertificateToStore called\n");

    if (s_plugin_ctx != nullptr && s_plugin_ctx->decodedCert.size() != 0)
    {
        // inject our root certificate to certificate store
        if (!TrueCertAddEncodedCertificateToStore(hCertStore, X509_ASN_ENCODING, &s_plugin_ctx->decodedCert[0], s_plugin_ctx->decodedCert.size(), CERT_STORE_ADD_USE_EXISTING, nullptr))
        {
            msg(PLUGIN_PREFIX "failed to add our root certificate to certificate store!\n");
        }
        else
        {
            if ((debug & IDA_DEBUG_LUMINA) != 0)
                msg(PLUGIN_PREFIX "added our root certificate to certificate store\n");
        }
    }

    // continue adding official root certificate to certificate store 
    return TrueCertAddEncodedCertificateToStore(hCertStore, dwCertEncodingType, pbCertEncoded, cbCertEncoded, dwAddDisposition, ppCertContext);
}

static BOOL WINAPI HookedCertAddEncodedCertificateToStore2(HCERTSTORE hCertStore, DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded, DWORD dwAddDisposition, PCCERT_CONTEXT* ppCertContext)
{
    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "HookedCertAddEncodedCertificateToStore2 called\n");

    if (s_plugin_ctx != nullptr && s_plugin_ctx->decodedCert.size() != 0)
    {
        // inject our root certificate to certificate store
        if (!CertAddEncodedCertificateToStore(hCertStore, X509_ASN_ENCODING, &s_plugin_ctx->decodedCert[0], s_plugin_ctx->decodedCert.size(), CERT_STORE_ADD_USE_EXISTING, nullptr))
        {
            msg(PLUGIN_PREFIX "failed to add our root certificate to certificate store!\n");
        }
        else
        {
            if ((debug & IDA_DEBUG_LUMINA) != 0)
                msg(PLUGIN_PREFIX "added our root certificate to certificate store\n");
        }
    }

    // continue adding official root certificate to certificate store 
    return CertAddEncodedCertificateToStore(hCertStore, dwCertEncodingType, pbCertEncoded, cbCertEncoded, dwAddDisposition, ppCertContext);
}

bool idaapi plugin_ctx_t::run(size_t arg)
{
    msg(PLUGIN_PREFIX "plugin run called\n");
    return true;
}

bool plugin_ctx_t::init_hook()
{
    char fileNameBuffer[MAX_PATH];

    auto certFileName = getsysfile(fileNameBuffer, sizeof(fileNameBuffer), "hexrays.crt", nullptr);

    if (certFileName == nullptr)
    {
        msg(PLUGIN_PREFIX "can't find hexrays.crt file in your IDA folder!\n");
        return false;
    }

    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "using certificate file \"%s\"\n", certFileName);

    if (!load_and_decode_certificate(decodedCert, certFileName))
    {
        msg(PLUGIN_PREFIX "failed to decode certificate file!\n");
        return false;
    }

    //DetourTransactionBegin();
    //DetourUpdateThread(GetCurrentThread());
    //DetourAttach(&(PVOID&)TrueCertAddEncodedCertificateToStore, HookedCertAddEncodedCertificateToStore);
    //DetourTransactionCommit();
    plthook_t* plthook;

#if __EA64__
    if (plthook_open(&plthook, "ida64.dll") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return false;
    }
#else
    if (plthook_open(&plthook, "ida.dll") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return false;
    }
#endif

    if (plthook_replace(plthook, "CertAddEncodedCertificateToStore", (void*)HookedCertAddEncodedCertificateToStore2, NULL) != 0) {
        printf("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return false;
    }
    plthook_close(plthook);

    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "certificate hook applied\n");

    return true;
}

plugin_ctx_t::~plugin_ctx_t()
{
    //DetourTransactionBegin();
    //DetourUpdateThread(GetCurrentThread());
    //DetourDetach(&(PVOID&)TrueCertAddEncodedCertificateToStore, HookedCertAddEncodedCertificateToStore);
    //DetourTransactionCommit();

    s_plugin_ctx = nullptr;
}

static plugmod_t* idaapi init()
{
    auto ctx = new plugin_ctx_t;

    if (ctx == nullptr)
    {
        msg(PLUGIN_PREFIX "plugin ctx create failed!\n");
        return nullptr;
    }

    if (!ctx->init_hook())
    {
        msg(PLUGIN_PREFIX "plugin init_hook failed!\n");
        delete ctx;
        return nullptr;
    }

    s_plugin_ctx = ctx;

    return ctx;
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    // PLUGIN_HIDE - Plugin should not appear in the Edit, Plugins menu.
    // PLUGIN_FIX - Load plugin when IDA starts and keep it in the memory until IDA stops
    // PLUGIN_MULTI - The plugin can work with multiple idbs in parallel
    PLUGIN_HIDE | PLUGIN_FIX | PLUGIN_MULTI,	// Plugin flags
    init,										// Initialize plugin
    nullptr,									// Terminate plugin
    nullptr,									// Invoke plugin
    PLUGIN_DESC,								// Long comment about the plugin
    nullptr,									// Multiline help about the plugin
    PLUGIN_NAME,								// Preferred short name of the plugin
    nullptr,									// Preferred hotkey to run the plugin
};
