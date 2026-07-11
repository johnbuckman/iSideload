//
//  native_bridge_zip.c
//  AltSign
//
//  Created by Magesh K on 25/02/26.
//


#include "native_bridge_zip.h"

#include "zip.h"
#include "unzip.h"

//#include <stdlib.h>

/* ---------- unzip ---------- */

native_bridge_unzFile native_bridge_unzOpen(const char *path)
{
    return (native_bridge_unzFile)unzOpen(path);
}

int native_bridge_unzClose(native_bridge_unzFile file)
{
    return unzClose((unzFile)file);
}

int native_bridge_unzGetGlobalInfo(native_bridge_unzFile file, void *info)
{
    return unzGetGlobalInfo((unzFile)file, (unz_global_info *)info);
}

int native_bridge_unzGoToFirstFile(native_bridge_unzFile file)
{
    return unzGoToFirstFile((unzFile)file);
}

int native_bridge_unzGoToNextFile(native_bridge_unzFile file)
{
    return unzGoToNextFile((unzFile)file);
}

int native_bridge_unzGetCurrentFileInfo(
    native_bridge_unzFile file,
    void *info,
    char *filename,
    unsigned long filenameBufferSize)
{
    return unzGetCurrentFileInfo(
        (unzFile)file,
        (unz_file_info *)info,
        filename,
        filenameBufferSize,
        NULL, 0, NULL, 0
    );
}

int native_bridge_unzOpenCurrentFile(native_bridge_unzFile file)
{
    return unzOpenCurrentFile((unzFile)file);
}

int native_bridge_unzReadCurrentFile(native_bridge_unzFile file, void *buffer, unsigned len)
{
    return unzReadCurrentFile((unzFile)file, buffer, len);
}

int native_bridge_unzCloseCurrentFile(native_bridge_unzFile file)
{
    return unzCloseCurrentFile((unzFile)file);
}

/* ---------- zip ---------- */

native_bridge_zipFile native_bridge_zipOpen(const char *path)
{
    return (native_bridge_zipFile)zipOpen(path, APPEND_STATUS_CREATE);
}

int native_bridge_zipOpenNewFileInZip(native_bridge_zipFile file, const char *filename)
{
    zip_fileinfo info = {0};

    return zipOpenNewFileInZip(
        (zipFile)file,
        filename,
        &info,
        NULL,0,NULL,0,NULL,
        Z_DEFLATED,
        Z_DEFAULT_COMPRESSION
    );
}

int native_bridge_zipWriteInFileInZip(native_bridge_zipFile file, const void *buffer, unsigned len)
{
    return zipWriteInFileInZip((zipFile)file, buffer, len);
}

int native_bridge_zipCloseFileInZip(native_bridge_zipFile file)
{
    return zipCloseFileInZip((zipFile)file);
}

int native_bridge_zipClose(native_bridge_zipFile file)
{
    return zipClose((zipFile)file, NULL);
}

int native_bridge_zipOpenNewFileInZipWithPermissions(native_bridge_zipFile file, const char *filename, uint32_t permissions)
{
    zip_fileinfo info = {0};
    info.external_fa = permissions << 16;

    return zipOpenNewFileInZip(
        (zipFile)file,
        filename,
        &info,
        NULL,0,NULL,0,NULL,
        Z_DEFLATED,
        Z_DEFAULT_COMPRESSION
    );
}

uint32_t native_bridge_unzGetCurrentFileExternalAttributes(native_bridge_unzFile file)
{
    unz_file_info info;
    if (unzGetCurrentFileInfo((unzFile)file, &info, NULL, 0, NULL, 0, NULL, 0) == 0) {
        return info.external_fa;
    }
    return 0;
}
