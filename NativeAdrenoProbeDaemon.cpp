// SPDX-License-Identifier: MIT
// Adreno probe daemon: started by launchd from an owner job (a union view over /System/Library/LaunchDaemons, see the boot-time addon
// mount), so it runs outside every sandbox profile. It waits for the Adreno accelerator service to appear, runs the shared userspace GPU
// test once, then writes the system log for the UFS log export (NativeOsLogExport.mm) and exits. The test result reaches the kernel through
// the driver's progress markers and SetMetadata.
//
// myron: while the log export runs, the daemon also publishes two diagnostic lines into the kernel's telemetry rows 45/46 for the boot
// page's PBF rows (myron-pbf-probe=1): PosterBoard's poster store as it exists at runtime (including the protection class getattrlist
// reports, which PosterBoard's viability check requires to be NSFileProtectionNone), and the store directory listing plus the first
// PosterBoard os_log line from the plain excerpt NativeOsLogExport.mm writes (pb.txt). PosterBoard is sandboxed with a data container:
// libsystem_containermanager's _container_init sets HOME to the container, and -[PBFPosterExtensionDataStoreXPCServiceGlue
// _baseDataStoreURL:] asks for NSApplicationSupportDirectory (14), so the store is <container>/Library/Application Support/
// PRBPosterExtensionDataStore/61. The daemon finds the container by its metadata plist. Markers (open type 0x4147xxxx) are recorded by
// the driver before it refuses the open, so this needs no user-client grant — the plugin publishes row 47 from the render server.
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <unistd.h>
#include "NativeAdrenoUserTest.h"

extern "C" void nativeOsLogExport();

using MatchingFn = void *(*)(const char *);
using GetServiceFn = unsigned (*)(unsigned, void *);
using OpenFn = int (*)(unsigned, unsigned, uint32_t, unsigned *);
using CloseFn = int (*)(unsigned);

namespace {

OpenFn gOpen;
CloseFn gClose;

const char *const kExcerpt = "/private/var/mobile/Library/Caches/com.apple.backboardd/m2v/zz-oslog/pb.txt";
const char *const kAppContainers = "/private/var/mobile/Containers/Data/Application";
const char *const kSystemContainers = "/private/var/containers/Data/System";
const char *const kHome = "/private/var/mobile";
const char *const kMetadata = ".com.apple.mobile_container_manager.metadata.plist";
// Below the container (or HOME): Library, Application Support, the store root, the version directory, the database.
const char *const kStoreTail[] = {
    "/Library",
    "/Library/Application Support",
    "/Library/Application Support/PRBPosterExtensionDataStore",
    "/Library/Application Support/PRBPosterExtensionDataStore/61",
    "/Library/Application Support/PRBPosterExtensionDataStore/61/PBFPosterExtensionDataStoreSQLiteDatabase.sqlite3",
};
char gStoreBase[512];      // the container (or HOME) composeStorage resolved last
char gStoreFlags[6];       // which kStoreTail entries exist below it

void *exportThread(void *) {
    nativeOsLogExport();
    return nullptr;
}

// One progress marker. The driver records it and refuses the open (so any returned connection is closed anyway).
void markValue(unsigned port, uint32_t value) {
    unsigned connection = 0;
    if (!gOpen || !port) return;
    const int opened = gOpen(port, mach_task_self(), 0x41470000u | (value & 0xffff), &connection);
    if (opened == 0 && connection && gClose) gClose(connection);
}

// One row of the kernel's telemetry table: 0xC000|row starts it, 0x8000|(a<<7)|b appends two characters (NativeAdrenoPublish.cpp).
void sendRow(unsigned port, unsigned row, const char *text) {
    if (row >= 48) return;
    markValue(port, 0xC000u | row);
    const size_t length = strlen(text) < 90 ? strlen(text) : 90;
    for (size_t i = 0; i < length; i += 2) {
        const unsigned a = (unsigned char)text[i] & 0x7f;
        const unsigned b = i + 1 < length ? (unsigned char)text[i + 1] & 0x7f : 0;
        markValue(port, 0x8000u | (a << 7) | b);
    }
}

// The first non-header line of pb.txt, or "nopb" when the excerpt was never written.
void firstLogLine(char *first, size_t cap) {
    const int fd = open(kExcerpt, O_RDONLY);
    if (fd < 0) {
        snprintf(first, cap, "nopb");
        return;
    }
    char log[1024] = {};
    const ssize_t n = read(fd, log, sizeof log - 1);
    close(fd);
    snprintf(first, cap, "nolog");
    if (n <= 0) return;
    char *p = log;
    while (*p == '#' || *p == '\r' || *p == '\n') {
        while (*p && *p != '\n') ++p;
        while (*p == '\n' || *p == '\r') ++p;
    }
    if (!*p) return;
    char *e = p;
    while (*e && *e != '\n' && *e != '\r') ++e;
    size_t len = (size_t)(e - p);
    if (len >= cap) len = cap - 1;
    memcpy(first, p, len);
    first[len] = 0;
}

// "PB <d>:<names> | <log line>", at most 90 bytes: the entries of the deepest existing store directory composeStorage found
// (d = V version dir, R store root, A Application Support, L Library, - none) and PosterBoard's first os_log line.
void composeDiagnostic(char *out, size_t cap) {
    int depth = -1;
    for (int i = 3; i >= 0 && depth < 0; --i) if (gStoreFlags[i] == '1') depth = i;
    char names[40] = {};
    if (depth >= 0) {
        char path[768];
        snprintf(path, sizeof path, "%s%s", gStoreBase, kStoreTail[depth]);
        if (DIR *dir = opendir(path)) {
            size_t used = 0;
            while (dirent *entry = readdir(dir)) {
                if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
                const int wrote = snprintf(names + used, sizeof names - used, "%s%s", used ? "," : "", entry->d_name);
                if (wrote < 0 || (size_t)wrote >= sizeof names - used) {
                    used = sizeof names - 1;
                    break;
                }
                used += (size_t)wrote;
            }
            closedir(dir);
            if (!used) snprintf(names, sizeof names, "empty");
        } else {
            snprintf(names, sizeof names, "e%d", errno);
        }
    }
    char first[96] = {};
    firstLogLine(first, sizeof first);
    snprintf(out, cap, "PB %c:%.38s | %.80s", depth < 0 ? '-' : "LARV"[depth], depth < 0 ? "" : names, first);
}

// True when a container's metadata plist names exactly com.apple.PosterBoard (binary plist: 0x5f 0x10 0x15 + the 21 bytes; XML:
// <string>com.apple.PosterBoard</string>), so com.apple.PosterBoard.* extension containers do not match.
bool isPosterBoardContainer(const char *container) {
    static char buffer[65536];
    char path[640];
    snprintf(path, sizeof path, "%s/%s", container, kMetadata);
    const int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    const ssize_t n = read(fd, buffer, sizeof buffer);
    close(fd);
    if (n <= 0) return false;
    static const char kBinary[] = "\x5f\x10\x15" "com.apple.PosterBoard";
    static const char kXml[] = "<string>com.apple.PosterBoard</string>";
    return memmem(buffer, (size_t)n, kBinary, sizeof kBinary - 1) || memmem(buffer, (size_t)n, kXml, sizeof kXml - 1);
}

// Counts the containers of one class directory and copies the PosterBoard one into found (if found is still empty).
unsigned findContainer(const char *root, char *found, size_t cap) {
    DIR *dir = opendir(root);
    if (!dir) return 0;
    unsigned count = 0;
    while (dirent *entry = readdir(dir)) {
        if (entry->d_name[0] == '.') continue;
        ++count;
        char container[512];
        snprintf(container, sizeof container, "%s/%s", root, entry->d_name);
        if (!found[0] && isPosterBoardContainer(container)) snprintf(found, cap, "%s", container);
    }
    closedir(dir);
    return count;
}

// The protection class getattrlist reports for path, as CFURL's NSURLFileProtectionKey sees it: '0'..'7', '-' when the kernel returns
// no ATTR_CMN_DATA_PROTECT_FLAGS (the volume supports no classes, CFURL reads nil), 'e' when getattrlist fails.
char protectionClass(const char *path) {
    struct attrlist list = {};
    list.bitmapcount = ATTR_BIT_MAP_COUNT;
    list.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_DATA_PROTECT_FLAGS;
    struct {
        uint32_t length;
        attribute_set_t returned;
        uint32_t protection;
    } buffer = {};
    if (getattrlist(path, &list, &buffer, sizeof buffer, 0) != 0) return 'e';
    if (!(buffer.returned.commonattr & ATTR_CMN_DATA_PROTECT_FLAGS)) return '-';
    return buffer.protection < 8 ? (char)('0' + buffer.protection) : '?';
}

// "DB <k><dir8> <LARVF> p<class> s<bytes> <magic> a<n> s<n>": where PosterBoard's store lives at runtime and how far it got.
//   k     a = PosterBoard's app data container, s = a system data container, h = none found (HOME /private/var/mobile checked)
//   dir8  the first 8 characters of that directory's name
//   LARVF 1/0 for Library, Application Support, PRBPosterExtensionDataStore, 61, the SQLite database
//   class protection class of the deepest existing store path (PosterBoard requires 4 = NSFileProtectionNone; '-' = none reported)
//   magic the database's first 15 bytes ("SQLite format 3" when it is one); a<n>/s<n> app/system container counts
void composeStorage(char *out, size_t cap) {
    char container[512] = {};
    const unsigned apps = findContainer(kAppContainers, container, sizeof container);
    char kind = container[0] ? 'a' : 'h';
    const unsigned systems = findContainer(kSystemContainers, container, sizeof container);
    if (kind == 'h' && container[0]) kind = 's';
    snprintf(gStoreBase, sizeof gStoreBase, "%s", container[0] ? container : kHome);
    unsigned long long size = 0;
    char magic[24] = {};
    char protection = 'n';
    for (unsigned i = 0; i < 5; ++i) {
        char path[768];
        snprintf(path, sizeof path, "%s%s", gStoreBase, kStoreTail[i]);
        struct stat st = {};
        gStoreFlags[i] = stat(path, &st) == 0 ? '1' : '0';
        if (gStoreFlags[i] == '1') protection = protectionClass(path);
        if (i == 4 && gStoreFlags[i] == '1') {
            size = (unsigned long long)st.st_size;
            const int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                const ssize_t n = read(fd, magic, 15);
                close(fd);
                magic[n > 0 ? n : 0] = 0;
            }
        }
    }
    gStoreFlags[5] = 0;
    for (char *c = magic; *c; ++c) if (*c < 32 || *c > 126) *c = '.';
    const char *name = strrchr(gStoreBase, '/');
    snprintf(out, cap, "DB %c%.8s %s p%c s%llu %s a%u s%u", kind, name ? name + 1 : gStoreBase, gStoreFlags, protection, size,
             magic[0] ? magic : "-", apps, systems);
}

}  // namespace

int main() {
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
    if (!iokit) return 1;
    auto matching = (MatchingFn)dlsym(iokit, "IOServiceMatching");
    auto getService = (GetServiceFn)dlsym(iokit, "IOServiceGetMatchingService");
    gOpen = (OpenFn)dlsym(iokit, "IOServiceOpen");
    gClose = (CloseFn)dlsym(iokit, "IOServiceClose");
    if (!matching || !getService) return 2;
    // The service is published a few seconds into boot (after the GPU is powered); poll for up to two minutes.
    unsigned port = 0;
    for (unsigned i = 0; i < 240 && !port; ++i) {
        port = getService(0, matching("IOAcceleratorES"));
        if (!port) usleep(500000);
    }
    // The export starts before the GPU test: a test that blocks must not keep PosterBoard's log from being written.
    pthread_t thread;
    const bool exporting = pthread_create(&thread, nullptr, exportThread, nullptr) == 0;
    const int status = !port ? 3 : adrenoUserTest(port, "adrenoprobed") >= 0 ? 0 : 4;
    if (!exporting) nativeOsLogExport();
    // 30 minutes at 10 s: the boot page takes over at t=180 s and keeps showing the latest line; one reboot clears it.
    for (unsigned i = 0; i < 180; ++i) {
        if (port) {
            char line[96];
            composeStorage(line, sizeof line);
            sendRow(port, 45, line);
            composeDiagnostic(line, sizeof line);
            sendRow(port, 46, line);
        }
        usleep(10000000);
    }
    return status;
}
