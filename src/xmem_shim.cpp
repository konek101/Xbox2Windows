// Desktop xmem.dll. The default allocation exports share the unhooked allocator.
// Call shapes come from the observed call sites, not from a published header:
//   XMemAlloc(size, attributes) and XMemFree(allocation, attributes): Bink and AMD callers.
//   XMemVirtualQuery(process, address, buffer): the four BVH callers pass no length, supply a
//     zeroed 64-byte buffer and test the 32-bit result.
//   XMemGetWorkingSetStatistics(selector, output): the seven AMD callers pass 0x20000001 and
//     read the 64-bit value at +8 (zero on failure).
// XMemAllocatePhysicalPages(flags, &count, pages) and XMemFreePhysicalPages(count, pages) follow the
// calls in the public Microsoft Xbox GDK samples; era_physical keeps the page bookkeeping.
// Graphics allocations go through era_title_gpu, which registers them with era_query and, once a
// D3D12 device is attached to the registry, gives them desktop GPU addresses. The exports are
// unchanged; nothing here loads D3D12. DXGI and gdi32 are delay-loaded.
#include "era_heap.h"
#include "era_physical.h"
#include "era_query.h"
#include "era_title_gpu.h"
#include "xmem_gpu_usage.h"

#include <cstdint>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace {
// The BVH callers' query buffer. era_query writes at most its first 0x31 bytes.
constexpr std::size_t query_buffer_bytes = 64;

bool is_graphics(std::uint64_t attributes) noexcept
{
    const auto type = era_heap::decode(attributes).memory_type;
    return type >= 1 && type <= 6;
}

// The selector the AMD callers pass, and the offset of the value they read.
constexpr UINT32 gpu_usage_selector = 0x20000001;
constexpr std::size_t gpu_usage_offset = 8;

// HRESULT E_NOTIMPL for the loader-gap exports that have no desktop implementation.
constexpr std::int32_t not_implemented = static_cast<std::int32_t>(0x80004001u);
}

extern "C" void* XMemAlloc(SIZE_T bytes, ULONGLONG attributes)
{
    void* allocation = era_heap::allocate(bytes, attributes);
    // Desktop policy: graphics memory types count as GPU-intended for XMemVirtualQuery.
    if (allocation && is_graphics(attributes) && !era_title_gpu::track(allocation, bytes)) {
        era_heap::release_with_attributes(allocation, attributes);
        return nullptr;
    }
    return allocation;
}

extern "C" void XMemFree(void* allocation, ULONGLONG attributes)
{
    if (allocation && is_graphics(attributes)) {
        era_title_gpu::untrack(allocation);
    }
    era_heap::release_with_attributes(allocation, attributes);
}

extern "C" BOOL XMemVirtualQuery(HANDLE process, LPCVOID address, void* buffer)
{
    return era_query::query(process, address, buffer, query_buffer_bytes) != 0;
}

// Desktop policy (docs/experiments.md): writes only +8, with this process's GPU memory in bytes;
// on failure the output is untouched and the callers use zero.
extern "C" BOOL XMemGetWorkingSetStatistics(UINT32 selector, void* statistics)
{
    if (!statistics) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    const auto bytes = selector == gpu_usage_selector ? xmem_gpu_usage::process_bytes() : std::nullopt;
    if (!bytes) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    std::memcpy(static_cast<unsigned char*>(statistics) + gpu_usage_offset, &*bytes, sizeof(*bytes));
    return TRUE;
}

namespace {
BOOL physical_result(era_physical::Status status) noexcept
{
    switch (status) {
    case era_physical::Status::ok:
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    case era_physical::Status::exhausted:
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
}
}

// Proposed desktop policy (docs/experiments.md, #880): 64 KiB pages only, all or nothing. On failure
// *count is 0 and the page array is untouched; console behavior on failure is not established.
extern "C" BOOL WINAPI XMemAllocatePhysicalPages(ULONG_PTR flags, PULONG_PTR count, PULONG_PTR pages)
{
    static_assert(sizeof(ULONG_PTR) == sizeof(std::uint64_t));
    // Observed Scarlett call at 0x5eb2780: XMemAllocatePhysicalPages(0x280, &page, context), where
    // the caller rounds a virtual address to a 64 KiB page, stores it in *count, and requires the
    // slot to come back unchanged with TRUE. Desktop has no physical-page query, so keep the
    // caller's synthetic page. Real allocations use the era_physical path below.
    constexpr ULONG_PTR observed_query_flags = 0x280;
    if (flags == observed_query_flags) {
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }
    return physical_result(era_physical::allocate(flags, reinterpret_cast<std::uint64_t*>(count),
                                                  reinterpret_cast<std::uint64_t*>(pages)));
}

// Proposed desktop policy: releases whole grants only (no partial release); any other array is
// refused without changing state. Whether the console permits partial release is not established.
extern "C" BOOL WINAPI XMemFreePhysicalPages(ULONG_PTR count, PULONG_PTR pages)
{
    return physical_result(era_physical::release(count, reinterpret_cast<const std::uint64_t*>(pages)));
}

extern "C" BOOL WINAPI XMemIsToolsMemAvailable()
{
    // The desktop runtime has no devkit tools-memory partition.
    return FALSE;
}

// XMemVirtualAlloc(address, size, flAllocationType, XMemFlags, flProtect). The observed recorder
// passes 0x20402000/0x21/0x4 and 0x20402000/0x3/0x801. The Xbox allocation type and protection
// carry console page-size and mapping bits that desktop VirtualAlloc rejects. Keep the standard
// reserve/commit state and a valid base protection so the title's multi-gigabyte reservations
// succeed. The XMemFlags page-kind details are not modeled here.
extern "C" void* XMemVirtualAlloc(void* address, SIZE_T bytes, DWORD allocation_type,
                                  ULONGLONG /*flags*/, DWORD protect)
{
    constexpr DWORD reserve = 0x00002000;
    constexpr DWORD commit = 0x00001000;
    constexpr DWORD reset = 0x00080000;
    constexpr DWORD top_down = 0x00100000;
    DWORD type = 0;
    if (allocation_type & reserve) type |= MEM_RESERVE;
    if (allocation_type & commit) type |= MEM_COMMIT;
    if (allocation_type & reset) type |= MEM_RESET;
    if (allocation_type & top_down) type |= MEM_TOP_DOWN;
    if (!type) type = MEM_RESERVE;
    DWORD base_protect = protect & 0xFFu;
    if (!base_protect) base_protect = PAGE_READWRITE;
    if (!(type & MEM_COMMIT)) base_protect = PAGE_NOACCESS;
    return VirtualAlloc(address, bytes, type, base_protect);
}

extern "C" std::int32_t XMemMapPhysicalPages(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG)
{
    return not_implemented;
}

extern "C" std::int32_t XMemMapPhysicalPagesScatter(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG)
{
    return not_implemented;
}

extern "C" std::int32_t XMemTransferMemory(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG)
{
    return not_implemented;
}
