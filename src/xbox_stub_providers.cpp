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
#include <cstddef>
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
//
// XGCreateTextureComputer must hand back a usable object: the title stores the out pointer and later
// calls a method through its vtable (observed `mov r10,[obj]; call [r10+0x40]` at game RVA
// 0x16f71ea). Failing closed left the caller's output slot untouched and the stale value was
// dereferenced. The desktop object is inert: IUnknown is refcounted and every other slot reports
// S_OK without doing work, so the caller sees a valid object graph and no GPU tiling is emulated.
namespace {
constexpr std::size_t inert_vtable_slots = 256;

struct inert_object {
    void** vtable;
    volatile LONG references;
};

std::int32_t WINAPI inert_method(void*) { return 0; }
std::uint32_t WINAPI inert_add_ref(inert_object* self)
{
    return static_cast<std::uint32_t>(InterlockedIncrement(&self->references));
}
std::uint32_t WINAPI inert_release(inert_object* self)
{
    // Process-lifetime singleton: clamp instead of freeing.
    const LONG remaining = InterlockedDecrement(&self->references);
    if (remaining < 0) {
        InterlockedExchange(&self->references, 0);
        return 0;
    }
    return static_cast<std::uint32_t>(remaining);
}
std::int32_t WINAPI inert_query_interface(inert_object* self, const GUID*, void** out)
{
    if (!out) return static_cast<std::int32_t>(0x80004003u); // E_POINTER
    *out = nullptr;
    inert_add_ref(self);
    *out = self;
    return 0;
}

inert_object* inert_singleton()
{
    static void* vtable[inert_vtable_slots] = {};
    static inert_object object = {nullptr, 1};
    static bool ready = [] {
        vtable[0] = reinterpret_cast<void*>(&inert_query_interface);
        vtable[1] = reinterpret_cast<void*>(&inert_add_ref);
        vtable[2] = reinterpret_cast<void*>(&inert_release);
        for (std::size_t slot = 3; slot < inert_vtable_slots; ++slot) {
            vtable[slot] = reinterpret_cast<void*>(&inert_method);
        }
        object.vtable = vtable;
        return true;
    }();
    (void)ready;
    return &object;
}
} // namespace

extern "C" {
std::int32_t WINAPI XGCreateTextureComputer(const void*, void** out)
{
    if (!out) return static_cast<std::int32_t>(0x80004003u);
    *out = nullptr;
    inert_object* object = inert_singleton();
    inert_add_ref(object);
    *out = object;
    return 0;
}
std::uint32_t WINAPI XGSuggestSwizzleMode(const void*) { return 0; }
}
#endif

#if defined(XBOX_STUB_XCRDAPI)
// xcrdapi.dll's DirectStorage factory lives in src/xcrdapi_factory.cpp so it can hand out a real
// factory object instead of failing closed.
#endif
