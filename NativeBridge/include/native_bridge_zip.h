//
//  native_bridge_zip.h
//  AltSign
//
//  Created by Magesh K on 25/02/26.
//


#pragma once
#include "native_bridge_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void* native_bridge_unzFile;
typedef void* native_bridge_zipFile;

/* unzip */

native_bridge_unzFile native_bridge_unzOpen(const char *path);
int native_bridge_unzClose(native_bridge_unzFile file);

int native_bridge_unzGetGlobalInfo(native_bridge_unzFile file, void *info);
int native_bridge_unzGoToFirstFile(native_bridge_unzFile file);
int native_bridge_unzGoToNextFile(native_bridge_unzFile file);

int native_bridge_unzGetCurrentFileInfo(
    native_bridge_unzFile file,
    void *info,
    char *filename,
    unsigned long filenameBufferSize
);

int native_bridge_unzOpenCurrentFile(native_bridge_unzFile file);
int native_bridge_unzReadCurrentFile(native_bridge_unzFile file, void *buffer, unsigned len);
int native_bridge_unzCloseCurrentFile(native_bridge_unzFile file);

/* zip */

native_bridge_zipFile native_bridge_zipOpen(const char *path);
int native_bridge_zipOpenNewFileInZip(native_bridge_zipFile file, const char *filename);
int native_bridge_zipOpenNewFileInZipWithPermissions(native_bridge_zipFile file, const char *filename, uint32_t permissions);
int native_bridge_zipWriteInFileInZip(native_bridge_zipFile file, const void *buffer, unsigned len);
int native_bridge_zipCloseFileInZip(native_bridge_zipFile file);
int native_bridge_zipClose(native_bridge_zipFile file);

uint32_t native_bridge_unzGetCurrentFileExternalAttributes(native_bridge_unzFile file);

#ifdef __cplusplus
}
#endif
