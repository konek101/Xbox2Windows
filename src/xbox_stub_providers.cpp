// Desktop loader-gap providers for the Xbox-only system modules the Scarlett executable imports.
//
// The exported names are the exact unresolved import-table entries measured by
// `tools/pe_inventory.py` on the inspected package (see docs/experiments.md, "Static executable
// intake"). The parameter shapes below are placeholders inferred from the names; they are not a
// published header or an observed Scarlett ABI. Every entry fails closed: the module exists so the
// Windows loader can resolve the import, but no console behavior is implemented. A call returns
// E_NOTIMPL, FALSE, zero or a null pointer, and never succeeds by accident.
//
// One translation unit builds all five providers. Each target defines exactly one XBOX_STUB_*
// macro and exports only that module's names through its .def file.
#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace {
// HRESULT E_NOTIMPL. Kept as an int32_t so the stub can return it without a COM header.
constexpr std::int32_t not_implemented = static_cast<std::int32_t>(0x80004001u);

void* pointer_failure() noexcept
{
    SetLastError(ERROR_NOT_SUPPORTED);
    return nullptr;
}
} // namespace

#if defined(XBOX_STUB_ACPHAL)
// acphal.dll: APU HAL and heap calls. Callers read an HRESULT, a BOOL, a handle or an address.
extern "C" {
std::int32_t WINAPI AcpHalAllocateShapeContexts(void*, std::uint32_t, void*) { return not_implemented; }
std::int32_t WINAPI AcpHalCreate(void*, const void*) { return not_implemented; }
std::int32_t WINAPI AcpHalReleaseShapeContexts(void*, void*) { return not_implemented; }
void* WINAPI ApuAlloc(std::uint64_t, std::uint64_t) { return pointer_failure(); }
std::int32_t WINAPI ApuCreateHeap(void*, const void*) { return not_implemented; }
void WINAPI ApuFree(void*) {}
std::int32_t WINAPI ApuIsVirtualAddressValid(std::uint64_t) { return 0; }
void* WINAPI ApuMapApuAddress(std::uint64_t, std::uint64_t) { return pointer_failure(); }
std::uint64_t WINAPI ApuMapVirtualAddress(void*, std::uint64_t) { return 0; }
}
#endif

#if defined(XBOX_STUB_CHAD)
// chad.dll: DSP activation and command submission. Callers read an HRESULT.
extern "C" {
std::int32_t WINAPI XDspActivate(void*, const void*) { return not_implemented; }
std::int32_t WINAPI XDspConnectWithMaximumStreamLimit(void*, std::uint32_t, void*) { return not_implemented; }
std::int32_t WINAPI XDspDeactivate(void*) { return not_implemented; }
std::int32_t WINAPI XDspDisconnect(void*) { return not_implemented; }
std::int32_t WINAPI XDspSubmitCommand(void*, const void*, std::uint32_t) { return not_implemented; }
}
#endif

#if defined(XBOX_STUB_XAPU)
// xapu.dll: APU command queue. Callers read an HRESULT or a result count.
extern "C" {
std::int32_t WINAPI XApuConnect(void*, const void*) { return not_implemented; }
std::int32_t WINAPI XApuDequeueResult(void*, void*) { return not_implemented; }
std::int32_t WINAPI XApuDisconnect(void*) { return not_implemented; }
std::int32_t WINAPI XApuEnqueueCommand(void*, const void*, std::uint32_t) { return not_implemented; }
std::uint32_t WINAPI XApuGetResultCount(void*) { return 0; }
}
#endif

#if defined(XBOX_STUB_XG_XS)
// xg_xs.dll: texture-computer creation and swizzle selection. Callers read an HRESULT or a mode.
extern "C" {
std::int32_t WINAPI XGCreateTextureComputer(const void*, void*) { return not_implemented; }
std::uint32_t WINAPI XGSuggestSwizzleMode(const void*) { return 0; }
}
#endif

#if defined(XBOX_STUB_XCRDAPI)
// xcrdapi.dll's DirectStorage factory lives in src/xcrdapi_factory.cpp so it can hand out a real
// factory object instead of failing closed.
#endif
