// Proves that every Xbox-only import requested by the inspected executable now binds to a desktop
// provider DLL, and that each provider applies its documented desktop policy. The names match the
// measured import table (tools/pe_inventory.py); the parameter shapes match
// src/xbox_stub_providers.cpp and are placeholders, not a verified Scarlett ABI. No package image
// is loaded or executed.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cwchar>

namespace {
constexpr std::int32_t not_implemented = static_cast<std::int32_t>(0x80004001u);
constexpr std::uint32_t not_implemented_bits = 0x80004001u;

extern "C" {
// acphal.dll
__declspec(dllimport) std::int32_t WINAPI AcpHalAllocateShapeContexts(void*, std::uint32_t, void*);
__declspec(dllimport) std::int32_t WINAPI AcpHalCreate(void*, const void*);
__declspec(dllimport) std::int32_t WINAPI AcpHalReleaseShapeContexts(void*, void*);
__declspec(dllimport) void* WINAPI ApuAlloc(std::uint64_t, std::uint64_t);
__declspec(dllimport) std::int32_t WINAPI ApuCreateHeap(void*, const void*);
__declspec(dllimport) void WINAPI ApuFree(void*);
__declspec(dllimport) std::int32_t WINAPI ApuIsVirtualAddressValid(std::uint64_t);
__declspec(dllimport) void* WINAPI ApuMapApuAddress(std::uint64_t, std::uint64_t);
__declspec(dllimport) std::uint64_t WINAPI ApuMapVirtualAddress(void*, std::uint64_t);

// chad.dll
__declspec(dllimport) std::int32_t WINAPI XDspActivate(void*, const void*);
__declspec(dllimport) std::int32_t WINAPI XDspConnectWithMaximumStreamLimit(void*, std::uint32_t, void*);
__declspec(dllimport) std::int32_t WINAPI XDspDeactivate(void*);
__declspec(dllimport) std::int32_t WINAPI XDspDisconnect(void*);
__declspec(dllimport) std::int32_t WINAPI XDspSubmitCommand(void*, const void*, std::uint32_t);

// xapu.dll
__declspec(dllimport) std::int32_t WINAPI XApuConnect(void*, const void*);
__declspec(dllimport) std::int32_t WINAPI XApuDequeueResult(void*, void*);
__declspec(dllimport) std::int32_t WINAPI XApuDisconnect(void*);
__declspec(dllimport) std::int32_t WINAPI XApuEnqueueCommand(void*, const void*, std::uint32_t);
__declspec(dllimport) std::uint32_t WINAPI XApuGetResultCount(void*);

// xg_xs.dll
__declspec(dllimport) std::int32_t WINAPI XGCreateTextureComputer(const void*, void*);
__declspec(dllimport) std::uint32_t WINAPI XGSuggestSwizzleMode(const void*);

// xcrdapi.dll
__declspec(dllimport) std::int32_t WINAPI DStorageGetFactory(const void*, void**);

// xmem.dll
__declspec(dllimport) void* WINAPI XMemAllocDefault(SIZE_T, ULONGLONG);
__declspec(dllimport) BOOL WINAPI XMemAllocatePhysicalPages(ULONG_PTR, PULONG_PTR, PULONG_PTR);
__declspec(dllimport) void WINAPI XMemFreeDefault(void*, ULONGLONG);
__declspec(dllimport) BOOL WINAPI XMemFreePhysicalPages(ULONG_PTR, PULONG_PTR);
__declspec(dllimport) BOOL WINAPI XMemIsToolsMemAvailable();
__declspec(dllimport) std::int32_t WINAPI XMemMapPhysicalPages(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG);
__declspec(dllimport) std::int32_t WINAPI XMemMapPhysicalPagesScatter(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG);
__declspec(dllimport) std::int32_t WINAPI XMemTransferMemory(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG);
__declspec(dllimport) void* WINAPI XMemVirtualAlloc(void*, SIZE_T, DWORD, ULONGLONG, DWORD);

// d3d12_xs.dll
__declspec(dllimport) std::int32_t WINAPI D3D12ConfigureVirtualMemoryX(void*, const void*);
}

struct binding {
    const wchar_t* module;
    const char* name;
    FARPROC address;
};

// Taking each address forces the linker to emit the import, so starting this process resolves all
// of them. The list is the union of unresolved edges for the executable in the measured inventory.
const binding bindings[] = {
    {L"acphal.dll", "AcpHalAllocateShapeContexts", reinterpret_cast<FARPROC>(&AcpHalAllocateShapeContexts)},
    {L"acphal.dll", "AcpHalCreate", reinterpret_cast<FARPROC>(&AcpHalCreate)},
    {L"acphal.dll", "AcpHalReleaseShapeContexts", reinterpret_cast<FARPROC>(&AcpHalReleaseShapeContexts)},
    {L"acphal.dll", "ApuAlloc", reinterpret_cast<FARPROC>(&ApuAlloc)},
    {L"acphal.dll", "ApuCreateHeap", reinterpret_cast<FARPROC>(&ApuCreateHeap)},
    {L"acphal.dll", "ApuFree", reinterpret_cast<FARPROC>(&ApuFree)},
    {L"acphal.dll", "ApuIsVirtualAddressValid", reinterpret_cast<FARPROC>(&ApuIsVirtualAddressValid)},
    {L"acphal.dll", "ApuMapApuAddress", reinterpret_cast<FARPROC>(&ApuMapApuAddress)},
    {L"acphal.dll", "ApuMapVirtualAddress", reinterpret_cast<FARPROC>(&ApuMapVirtualAddress)},
    {L"chad.dll", "XDspActivate", reinterpret_cast<FARPROC>(&XDspActivate)},
    {L"chad.dll", "XDspConnectWithMaximumStreamLimit", reinterpret_cast<FARPROC>(&XDspConnectWithMaximumStreamLimit)},
    {L"chad.dll", "XDspDeactivate", reinterpret_cast<FARPROC>(&XDspDeactivate)},
    {L"chad.dll", "XDspDisconnect", reinterpret_cast<FARPROC>(&XDspDisconnect)},
    {L"chad.dll", "XDspSubmitCommand", reinterpret_cast<FARPROC>(&XDspSubmitCommand)},
    {L"xapu.dll", "XApuConnect", reinterpret_cast<FARPROC>(&XApuConnect)},
    {L"xapu.dll", "XApuDequeueResult", reinterpret_cast<FARPROC>(&XApuDequeueResult)},
    {L"xapu.dll", "XApuDisconnect", reinterpret_cast<FARPROC>(&XApuDisconnect)},
    {L"xapu.dll", "XApuEnqueueCommand", reinterpret_cast<FARPROC>(&XApuEnqueueCommand)},
    {L"xapu.dll", "XApuGetResultCount", reinterpret_cast<FARPROC>(&XApuGetResultCount)},
    {L"xg_xs.dll", "XGCreateTextureComputer", reinterpret_cast<FARPROC>(&XGCreateTextureComputer)},
    {L"xg_xs.dll", "XGSuggestSwizzleMode", reinterpret_cast<FARPROC>(&XGSuggestSwizzleMode)},
    {L"xcrdapi.dll", "DStorageGetFactory", reinterpret_cast<FARPROC>(&DStorageGetFactory)},
    {L"xmem.dll", "XMemAllocDefault", reinterpret_cast<FARPROC>(&XMemAllocDefault)},
    {L"xmem.dll", "XMemAllocatePhysicalPages", reinterpret_cast<FARPROC>(&XMemAllocatePhysicalPages)},
    {L"xmem.dll", "XMemFreeDefault", reinterpret_cast<FARPROC>(&XMemFreeDefault)},
    {L"xmem.dll", "XMemFreePhysicalPages", reinterpret_cast<FARPROC>(&XMemFreePhysicalPages)},
    {L"xmem.dll", "XMemIsToolsMemAvailable", reinterpret_cast<FARPROC>(&XMemIsToolsMemAvailable)},
    {L"xmem.dll", "XMemMapPhysicalPages", reinterpret_cast<FARPROC>(&XMemMapPhysicalPages)},
    {L"xmem.dll", "XMemMapPhysicalPagesScatter", reinterpret_cast<FARPROC>(&XMemMapPhysicalPagesScatter)},
    {L"xmem.dll", "XMemTransferMemory", reinterpret_cast<FARPROC>(&XMemTransferMemory)},
    {L"xmem.dll", "XMemVirtualAlloc", reinterpret_cast<FARPROC>(&XMemVirtualAlloc)},
    {L"d3d12_xs.dll", "D3D12ConfigureVirtualMemoryX", reinterpret_cast<FARPROC>(&D3D12ConfigureVirtualMemoryX)},
};

bool same_bits(std::int32_t value)
{
    return static_cast<std::uint32_t>(value) == not_implemented_bits;
}

bool bindings_resolve()
{
    for (const auto& item : bindings) {
        HMODULE module = GetModuleHandleW(item.module);
        if (!module) {
            std::fwprintf(stderr, L"module not loaded: %ls\n", item.module);
            return false;
        }
        FARPROC exported = GetProcAddress(module, item.name);
        if (!exported) {
            std::fprintf(stderr, "missing export: %ls!%s\n", item.module, item.name);
            return false;
        }
        // The imported address must be the provider's own export, not another module's.
        HMODULE owner = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(item.address), &owner) ||
            owner != module || exported != item.address) {
            std::fprintf(stderr, "wrong provider for %ls!%s\n", item.module, item.name);
            return false;
        }
    }
    return true;
}

bool applies_desktop_policy()
{
    return same_bits(AcpHalCreate(nullptr, nullptr)) &&
           same_bits(XDspActivate(nullptr, nullptr)) &&
           same_bits(XApuConnect(nullptr, nullptr)) &&
           XApuGetResultCount(nullptr) == 0 &&
           same_bits(XGCreateTextureComputer(nullptr, nullptr)) &&
           XGSuggestSwizzleMode(nullptr) == 0 &&
           same_bits(XMemTransferMemory(0, 0, 0, 0)) &&
           XMemIsToolsMemAvailable() == FALSE &&
           ApuIsVirtualAddressValid(0) == 0 &&
           // Desktop D3D12 owns device virtual memory, so the configuration step succeeds.
           D3D12ConfigureVirtualMemoryX(nullptr, nullptr) == S_OK;
}
bool virtual_alloc_reserves()
{
    void* reservation = XMemVirtualAlloc(nullptr, 1u << 20, MEM_RESERVE, 0, PAGE_READWRITE);
    return reservation && VirtualFree(reservation, 0, MEM_RELEASE) != 0;
}

bool dstorage_factory()
{
    void* raw = nullptr;
    if (DStorageGetFactory(nullptr, &raw) != S_OK || raw == nullptr) return false;
    auto** vtable = *reinterpret_cast<void***>(raw);
    using set_staging_buffer_size = std::int32_t(WINAPI*)(void*, std::uint32_t);
    using release = std::uint32_t(WINAPI*)(void*);
    const bool sized =
        reinterpret_cast<set_staging_buffer_size>(vtable[8])(raw, 0x02000000u) == S_OK;
    reinterpret_cast<release>(vtable[2])(raw);
    return sized;
}
} // namespace

int main()
{
    if (!bindings_resolve()) return 1;
    if (!applies_desktop_policy()) return 2;
    if (!dstorage_factory()) return 3;
    if (!virtual_alloc_reserves()) return 4;
    std::printf("xbox_stub_providers: %zu imports resolved; every probed call applied its "
                "desktop policy, XMemVirtualAlloc reserves, and the DirectStorage factory accepts "
                "its staging-buffer size\n",
                sizeof(bindings) / sizeof(bindings[0]));
    return 0;
}
