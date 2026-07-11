//
//  native_bridge_zsign.cpp
//  AltSign
//
//  Drop-in replacement for native_bridge_ldid.cpp that signs with zsign
//  (SHA-256-primary CodeDirectory, iOS 12+/26-compatible) instead of the
//  legacy rileytestut/ldid (SHA-1-primary, rejected by iOS 16+).
//
//  Same C ABI as native_bridge_ldid_sign(): ALTSigner already embeds the
//  mobileprovision, filters entitlements and enumerates extensions, then calls
//  us to produce the actual code signatures. We hand the app folder to zsign's
//  ZBundle::SignFolder.
//

#include "native_bridge_zsign.h"

// zsign core (added as source to the SwiftPM target in place of Dependencies/ldid)
#include "openssl.h"   // ZSignAsset
#include "bundle.h"    // ZBundle

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <unistd.h>

namespace {

// Write a buffer to a fresh temp file; returns the path (empty on failure).
std::string WriteTemp(const char *suffix, const void *data, size_t len) {
    char tmpl[] = "/tmp/altsign_zsignXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return "";
    std::string path = tmpl;
    if (suffix && *suffix) {
        std::string np = path + suffix;
        ::rename(path.c_str(), np.c_str());
        path = np;
    }
    ::close(fd);
    std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc);
    if (data && len) out.write(reinterpret_cast<const char *>(data), len);
    out.close();
    return path;
}

} // namespace

/* --------------------------------------------------------- */
/* C ABI                                                     */
/* --------------------------------------------------------- */

extern "C" {

int native_bridge_zsign_sign(
    const char *appPath,
    const uint8_t *keyData,
    int32_t keyLen,
    const char *(*entitlement_callback)(const char *relativePath, void *context),
    void *entitlement_context,
    void (*progress_callback)(void *context),
    void *progress_context,
    char **errorMessage
){
    std::string p12Path, entPath;
    try {
        if (!appPath) {
            if (errorMessage) *errorMessage = strdup("Invalid arguments: appPath is null");
            return 1;
        }

        // ALTSigner/LdidBridge passes the bundle path with a trailing slash
        // (ldid wanted it); zsign's FindAppFolder needs it without. Normalize.
        std::string appDir(appPath);
        while (appDir.size() > 1 && appDir.back() == '/') appDir.pop_back();
        appPath = appDir.c_str();

        const bool adhoc = (keyData == nullptr || keyLen <= 0);

        // The p12 (cert+key) that ALTSigner passes as keyData. zsign auto-detects
        // a combined PKCS#12 when handed as the private-key file (like `zsign -k x.p12`).
        if (!adhoc) {
            p12Path = WriteTemp(".p12", keyData, static_cast<size_t>(keyLen));
            if (p12Path.empty()) {
                if (errorMessage) *errorMessage = strdup("zsign bridge: failed to stage p12");
                return 2;
            }
        }

        // ALTSigner supplies entitlements per Mach-O path; zsign takes one
        // entitlements file for the app and derives nested. Query the callback
        // for the app bundle itself (main executable) and use that.
        std::string entitlements;
        if (entitlement_callback) {
            const char *res = entitlement_callback(appPath, entitlement_context);
            if (res) entitlements = res;
        }
        if (!entitlements.empty()) {
            entPath = WriteTemp(".plist", entitlements.data(), entitlements.size());
        }

        // ALTSigner has already written embedded.mobileprovision into the .app;
        // zsign's ZSignAsset::Init wants the provision path explicitly (it needs
        // the team id for the signer). Locate it inside the bundle.
        std::string provPath;
        if (!adhoc) {
            std::string cand = std::string(appPath) + "/embedded.mobileprovision";
            if (access(cand.c_str(), R_OK) == 0) provPath = cand;
        }

        ZSignAsset asset;
        // Init(cert, pkey, prov, entitle, password, bAdhoc, bSHA256Only, bSingleBinary)
        // bSHA256Only = true -> the modern CodeDirectory iOS 26 accepts.
        if (!asset.Init(/*cert*/"", /*pkey*/p12Path, /*prov*/provPath, /*entitle*/entPath,
                        /*password*/"", /*bAdhoc*/adhoc, /*bSHA256Only*/true,
                        /*bSingleBinary*/false)) {
            if (errorMessage) *errorMessage = strdup("zsign bridge: ZSignAsset::Init failed (bad cert/key/provision?)");
            if (!p12Path.empty()) ::unlink(p12Path.c_str());
            if (!entPath.empty())  ::unlink(entPath.c_str());
            return 3;
        }

        if (progress_callback) progress_callback(progress_context);

        ZBundle bundle;
        bool ok = bundle.SignFolder(
            &asset,
            appPath,
            /*strBundleId*/"",        // keep existing
            /*strBundleVersion*/"",   // keep existing
            /*strDisplayName*/"",     // keep existing
            /*arrDylibFiles*/std::vector<std::string>(),
            /*arrRemoveDylibNames*/std::vector<std::string>(),
            /*bForce*/true,
            /*bWeakInject*/false,
            /*bEnableCache*/false,
            /*bRemoveProvision*/false);

        if (progress_callback) progress_callback(progress_context);

        if (!p12Path.empty()) ::unlink(p12Path.c_str());
        if (!entPath.empty())  ::unlink(entPath.c_str());

        if (!ok) {
            if (errorMessage) *errorMessage = strdup("zsign bridge: SignFolder failed");
            return 4;
        }
        return 0;
    }
    catch (const std::exception &e) {
        if (!p12Path.empty()) ::unlink(p12Path.c_str());
        if (!entPath.empty())  ::unlink(entPath.c_str());
        if (errorMessage) *errorMessage = strdup(e.what());
        return 5;
    }
}

} // extern "C"
