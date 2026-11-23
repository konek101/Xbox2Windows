// Desktop d3d12_xs.dll exporting the two root-signature functions the package DLLs import by name.
// Observed call sites (docs/experiments.md):
//   D3D12SerializeVersionedRootSignature: XboxBvhBuilder.dll (0xc2d0/0xc32f) copies a 48-byte
//     descriptor, sets console flag bits 0x03000000 at +0x28, and passes a null error output.
//   D3D12CreateRootSignatureDeserializer: amd_fidelityfx_upscaler_xbox.dll (0x4f88) reads a
//     serialized root signature from an embedded container and retrieves the descriptor interface.
#include <windows.h>
#include <unknwn.h>
#include <d3d12.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>

namespace {
// Observed console root-signature flag bits set by XboxBvhBuilder.dll.
// Unobserved bits are left untouched so desktop d3d12.dll still rejects unknown flags.
constexpr std::uint32_t observed_console_flags = 0x03000000u;

static_assert(offsetof(D3D12_VERSIONED_ROOT_SIGNATURE_DESC, Desc_1_0) +
              offsetof(D3D12_ROOT_SIGNATURE_DESC, Flags) == 0x28);
static_assert(offsetof(D3D12_VERSIONED_ROOT_SIGNATURE_DESC, Desc_1_1) +
              offsetof(D3D12_ROOT_SIGNATURE_DESC1, Flags) == 0x28);

// ---------------------------------------------------------------------------------------------
// Xbox device request proxy.
//
// The title asks D3D12XboxCreateDevice for the Xbox device IID {5405c344-d457-444e-b4dd-2366e45aee39}
// with adapter=nullptr and a non-null console parameter block. Desktop D3D12 cannot produce that
// interface, so the shim creates a normal FL12_0 ID3D12Device and returns a proxy:
//
//   * The proxy owns one reference on the real desktop device and releases it when the proxy's
//     IUnknown reference count reaches zero.
//   * Slots 0..2 are proxy QueryInterface/AddRef/Release. QueryInterface answers the Xbox IID,
//     IID_ID3D12Device and IID_IUnknown, and returns E_NOINTERFACE for anything else.
//   * Slots 3..43 are the fixed ID3D12Object + ID3D12Device methods from the Windows SDK
//     (3 IUnknown + 4 ID3D12Object + 37 ID3D12Device = 44 slots). Each slot is a generated x64
//     thunk that replaces the proxy `this` with the real desktop device and tail-jumps to the
//     matching desktop vtable slot, so the desktop method never runs with a proxy `this`.
//   * Slots 44..139 are reserved for the Xbox-appended methods whose layout is not known yet.
//     Every one of them lands on a generated stub that logs the slot number and returns
//     E_NOTIMPL. Nothing in that range is ever executed as code from the proxy or the caller.
//   * Slot 73 (offset 0x248), measured in the title, is the exception: it creates a real desktop
//     command list and returns a forwarding proxy over it. See the command-list section below.
//
// This is deliberately a prefix-compatible assumption: the Xbox interface is treated as
// ID3D12Device followed by appended methods. `desktop_device_slots` and `xbox_appended_slots`
// below are the single place to correct once the real Xbox vtable layout is measured.
// ---------------------------------------------------------------------------------------------

// IID requested by the observed Scarlett D3D12XboxCreateDevice call.
constexpr GUID xbox_device_iid = {0x5405c344u, 0xd457u, 0x444eu,
                                  {0xb4u, 0xddu, 0x23u, 0x66u, 0xe4u, 0x5au, 0xeeu, 0x39u}};

// Windows SDK 10.0.26100 ID3D12Device: 3 IUnknown + 4 ID3D12Object + 37 ID3D12Device methods.
constexpr std::size_t desktop_device_slots = 44;
// Slack for the Xbox-appended methods. Unknown today; fail closed across this whole range.
constexpr std::size_t xbox_appended_slots = 96;
constexpr std::size_t proxy_vtable_slots = desktop_device_slots + xbox_appended_slots;

// Method indices 19 and 20 (slots 25 and 26) return D3D12_RESOURCE_ALLOCATION_INFO and
// D3D12_HEAP_PROPERTIES by value. Under the Microsoft x64 ABI those use a hidden return buffer in
// RCX and therefore carry `this` in RDX. Their thunks adjust RDX instead of RCX.
constexpr std::size_t get_resource_allocation_info_slot = 25;
constexpr std::size_t get_custom_heap_properties_slot = 26;

struct ProxyDevice {
    void** vtable;           // +0  COM vtable pointer seen by the caller.
    volatile LONG references; // +8  proxy IUnknown reference count.
    ID3D12Device* real;      // +16 owned desktop device (offset used by the thunks).
    void* thunk_memory;      // executable thunk block.
    void** vtable_memory;    // backing storage for `vtable`.

    // Step 3b replacement binding objects. They are created once under this lock and stay
    // valid for the proxy lifetime; the replacement PSO and the command-list proxy both
    // reference them. The borrowed pointers below are owned by the title, not by the shim.
    SRWLOCK replacement_resources_lock;
    bool replacement_resources_attempted;
    ID3D12RootSignature* replacement_root_signature; // SRV t0 at parameter 0, UAV u0 at 1.
    ID3D12Resource* replacement_uav;                 // 16 MiB dummy, state UNORDERED_ACCESS.
    ID3D12PipelineState* replacement_pso;            // borrowed: the created replacement PSO.
    ID3D12RootSignature* replacement_game_root_signature; // borrowed: desc->pRootSignature.
};

constexpr std::size_t forward_thunk_bytes = 23;
constexpr std::size_t xbox_stub_bytes = 22;
constexpr std::size_t thunk_block_bytes =
    forward_thunk_bytes * (desktop_device_slots - 3) + xbox_stub_bytes * xbox_appended_slots;
static_assert(sizeof(void*) == 8, "the forwarding thunks are x64-specific");

// ---------------------------------------------------------------------------------------------
// Bounded diagnostic log: OutputDebugString plus %TEMP%\d3d12_xs-shim.log, capped by message count
// and file size. Only IIDs, slot numbers and pointers are written.
// ---------------------------------------------------------------------------------------------
constexpr LONG max_log_messages = 16384;
constexpr LONGLONG max_log_file_bytes = 4 * 1024 * 1024;
volatile LONG log_message_count = 0;
SRWLOCK log_lock = SRWLOCK_INIT;

void write_log(const char* line)
{
    if (InterlockedIncrement(&log_message_count) > max_log_messages) return;

    OutputDebugStringA(line);

    wchar_t temp_path[MAX_PATH];
    const DWORD temp_length = GetTempPathW(MAX_PATH, temp_path);
    if (temp_length == 0 || temp_length >= MAX_PATH) return;

    wchar_t log_path[MAX_PATH];
    if (swprintf_s(log_path, MAX_PATH, L"%sd3d12_xs-shim.log", temp_path) < 0) return;

    AcquireSRWLockExclusive(&log_lock);
    HANDLE file = CreateFileW(log_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size{};
        if (GetFileSizeEx(file, &size) && size.QuadPart < max_log_file_bytes) {
            DWORD written = 0;
            WriteFile(file, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
        }
        CloseHandle(file);
    }
    ReleaseSRWLockExclusive(&log_lock);
}

void format_iid(const GUID& iid, char* out, std::size_t size)
{
    std::snprintf(out, size, "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
                  static_cast<unsigned long>(iid.Data1), static_cast<unsigned>(iid.Data2),
                  static_cast<unsigned>(iid.Data3), iid.Data4[0], iid.Data4[1], iid.Data4[2],
                  iid.Data4[3], iid.Data4[4], iid.Data4[5], iid.Data4[6], iid.Data4[7]);
}

void destroy_proxy(ProxyDevice* proxy)
{
    if (proxy->real) proxy->real->Release();
    if (proxy->replacement_uav) proxy->replacement_uav->Release();
    if (proxy->replacement_root_signature) proxy->replacement_root_signature->Release();
    if (proxy->thunk_memory) VirtualFree(proxy->thunk_memory, 0, MEM_RELEASE);
    delete[] proxy->vtable_memory;
    delete proxy;
}

ULONG WINAPI proxy_add_ref(ProxyDevice* proxy)
{
    return static_cast<ULONG>(InterlockedIncrement(&proxy->references));
}

ULONG WINAPI proxy_release(ProxyDevice* proxy)
{
    const LONG remaining = InterlockedDecrement(&proxy->references);
    if (remaining == 0) destroy_proxy(proxy);
    return static_cast<ULONG>(remaining);
}

HRESULT WINAPI proxy_query_interface(ProxyDevice* proxy, REFIID iid, void** out)
{
    if (!out) return E_POINTER;
    *out = nullptr;
    if (IsEqualIID(iid, __uuidof(IUnknown)) || IsEqualIID(iid, __uuidof(ID3D12Device)) ||
        IsEqualIID(iid, xbox_device_iid)) {
        proxy_add_ref(proxy);
        *out = proxy;
        return S_OK;
    }
    return E_NOINTERFACE;
}

// Tail-called by an Xbox appended-slot stub. RDX holds the slot number (overwriting the original
// second argument is safe because the slot is unimplemented); RCX still holds whatever the caller
// passed there, which for sret methods is the hidden return buffer. Do not dereference it.
// Console device slots from #44 upward are the Xbox extensions. The public XCL reference records that
// unimplemented extension slots answer S_OK rather than an error, so a title probing a capability is
// not pushed onto an error path. Slots with a measured meaning keep their dedicated handlers.
HRESULT WINAPI unimplemented_xbox_slot(ProxyDevice* self, std::uintptr_t slot)
{
    char line[192];
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: xbox vtable slot %llu called (this=%p) -> S_OK (stub)\n",
                  static_cast<unsigned long long>(slot), static_cast<void*>(self));
    write_log(line);
    return S_OK;
}

void put_u32(std::uint8_t*& cursor, std::uint32_t value)
{
    cursor[0] = static_cast<std::uint8_t>(value);
    cursor[1] = static_cast<std::uint8_t>(value >> 8);
    cursor[2] = static_cast<std::uint8_t>(value >> 16);
    cursor[3] = static_cast<std::uint8_t>(value >> 24);
    cursor += 4;
}

void put_u64(std::uint8_t*& cursor, std::uint64_t value)
{
    for (unsigned shift = 0; shift != 64; shift += 8) {
        *cursor++ = static_cast<std::uint8_t>(value >> shift);
    }
}

// mov rax, [this_reg + real_offset]; mov this_reg, rax; mov rax, [rax]; jmp [rax + slot*8]
std::uint8_t* emit_forward_thunk(std::uint8_t* code, std::uint32_t real_offset, std::uint32_t slot,
                                 bool this_in_second_arg)
{
    if (this_in_second_arg) {
        // Caller convention measured at game RVA 0x24786ef: RCX = hidden return buffer,
        // RDX = proxy. Desktop sret methods expect RCX = real device, RDX = return buffer.
        // mov rax, [rdx+real_offset]
        *code++ = 0x48; *code++ = 0x8B; *code++ = 0x82;
        put_u32(code, real_offset);
        // xchg rcx, rdx  (rdx becomes the caller's return buffer)
        *code++ = 0x48; *code++ = 0x87; *code++ = 0xD1;
        // mov rcx, rax  (rcx becomes the real device)
        *code++ = 0x48; *code++ = 0x89; *code++ = 0xC1;
    } else {
        // mov rax, [rcx+real_offset]
        *code++ = 0x48; *code++ = 0x8B; *code++ = 0x81;
        put_u32(code, real_offset);
        // mov rcx, rax
        *code++ = 0x48; *code++ = 0x89; *code++ = 0xC1;
        // Pad to the fixed thunk size.
        *code++ = 0x90; *code++ = 0x90; *code++ = 0x90;
    }
    // mov rax, [rax]
    *code++ = 0x48; *code++ = 0x8B; *code++ = 0x00;
    // jmp qword ptr [rax+slot*8]
    *code++ = 0x48; *code++ = 0xFF; *code++ = 0xA0;
    put_u32(code, slot * 8u);
    return code;
}

// mov rdx, slot; mov rax, handler; jmp rax
std::uint8_t* emit_xbox_stub(std::uint8_t* code, std::uintptr_t slot, const void* handler)
{
    *code++ = 0x48; *code++ = 0xBA;
    put_u64(code, static_cast<std::uint64_t>(slot));
    *code++ = 0x48; *code++ = 0xB8;
    put_u64(code, static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handler)));
    *code++ = 0xFF; *code++ = 0xE0;
    return code;
}

// ---------------------------------------------------------------------------------------------
// Slot-73 command-list proxy.
//
// The observed title calls Xbox device vtable slot 73 (offset 0x248), CreateCommandListX, at game
// RVA 0x2478b71:
//   RCX = device proxy
//   RDX = 16-byte console descriptor {type, flags, nodeMask, ...}
//   R8  = allocator returned by device slot 9
//   R9  = initial PSO (0 in the observed call)
//   [rsp+0x28] = REFIID {c3827890-4024-474c-98cf-645b51dc4874}
//   [rsp+0x30] = void** out
//
// The desktop method has no console descriptor, so the type and node mask are translated and a
// normal desktop list is created with ID3D12Device::CreateCommandList. The returned object is a
// per-call proxy:
//
//   * Slots 0..2 implement QueryInterface/AddRef/Release. QueryInterface answers the console
//     command-list IID, IID_ID3D12GraphicsCommandList6 (when the SDK declares it),
//     IID_ID3D12GraphicsCommandList and IUnknown.
//   * Slots 3..41 are the fixed base ID3D12GraphicsCommandList methods (3 IUnknown + 4
//     ID3D12Object + 1 ID3D12DeviceChild + 1 ID3D12CommandList + 32 ID3D12GraphicsCommandList),
//     including slot 9 Close, slot 14 Dispatch and every compute root binding. Each slot is a
//     generated x64 thunk that swaps the proxy `this` for the real desktop list and tail-jumps to
//     the same desktop vtable slot.
//   * Slot 25 SetPipelineState, slot 29 SetComputeRootSignature and slot 41
//     SetComputeRootUnorderedAccessView instead run shim handlers. They track whether the list is
//     executing the replacement PSO, substitute the desktop replacement root signature for the
//     title's root signature, and bind the dummy UAV at parameter 1. The other root methods
//     (descriptor table 28/31, SRV 39, Dispatch 14) are forwarded unchanged.
//   * Slots 42..255 are console reordering / unknown methods. Their stubs log the slot and return
//     E_NOTIMPL, except the measured tail calls slot 131 (0x418) and slot 132 (0x420), which have
//     no out parameter and whose return values are ignored: those log and return S_OK.
//     Everything from 42 upward stays fail-closed; no console-only slot is forwarded.
//
// The real list is released when the proxy refcount reaches zero. One proxy is created per
// CreateCommandListX call; nothing here is a singleton.
// ---------------------------------------------------------------------------------------------
constexpr std::size_t create_xbox_slot73_index = 73;
static_assert(create_xbox_slot73_index >= desktop_device_slots &&
                  create_xbox_slot73_index < proxy_vtable_slots,
              "slot 73 must be an Xbox-appended slot of the device proxy");

// Console command-list IID requested by the observed CreateCommandListX call.
constexpr GUID xbox_command_list_iid = {0xc3827890u, 0x4024u, 0x474cu,
                                        {0x98u, 0xcfu, 0x64u, 0x5bu,
                                         0x51u, 0xdcu, 0x48u, 0x74u}};

// Observed 16-byte console descriptor: {type, flags, nodeMask, reserved}.
struct XboxCommandListDesc {
    std::uint32_t type;      // +0
    std::uint32_t flags;     // +4
    std::uint32_t node_mask; // +8
    std::uint32_t reserved;  // +12
};
static_assert(sizeof(XboxCommandListDesc) == 16, "the console descriptor is 16 bytes");
static_assert(offsetof(XboxCommandListDesc, node_mask) == 8, "nodeMask is at +8");

constexpr std::size_t command_list_vtable_slots = 256;
constexpr std::size_t command_list_forward_first = 3;
constexpr std::size_t command_list_forward_last = 41;
constexpr std::size_t command_list_stub_first = command_list_forward_last + 1;
constexpr std::size_t command_list_forward_count =
    command_list_forward_last - command_list_forward_first + 1;
constexpr std::size_t command_list_stub_count =
    command_list_vtable_slots - command_list_stub_first;
constexpr std::size_t command_list_thunk_block_bytes =
    forward_thunk_bytes * command_list_forward_count + xbox_stub_bytes * command_list_stub_count;
// Desktop ID3D12GraphicsCommandList slots re-implemented by the shim.
constexpr std::size_t command_list_set_pipeline_state_slot = 25;
constexpr std::size_t command_list_set_compute_root_signature_slot = 29;
constexpr std::size_t command_list_set_compute_root_uav_slot = 41;
constexpr std::size_t command_list_set_root_constants_slot = 40;
static_assert(command_list_set_pipeline_state_slot >= command_list_forward_first &&
                  command_list_set_pipeline_state_slot <= command_list_forward_last,
              "SetPipelineState must be inside the forwarded range");
static_assert(command_list_set_compute_root_signature_slot >= command_list_forward_first &&
                  command_list_set_compute_root_signature_slot <= command_list_forward_last,
              "SetComputeRootSignature must be inside the forwarded range");
static_assert(command_list_set_compute_root_uav_slot >= command_list_forward_first &&
                  command_list_set_compute_root_uav_slot <= command_list_forward_last,
              "SetComputeRootUnorderedAccessView must be inside the forwarded range");
constexpr std::size_t command_list_tail_slot_131 = 0x418 / sizeof(void*);
constexpr std::size_t command_list_tail_slot_132 = 0x420 / sizeof(void*);
static_assert(command_list_tail_slot_131 == 131, "0x418 is slot 131");
static_assert(command_list_tail_slot_132 == 132, "0x420 is slot 132");
static_assert(command_list_vtable_slots > command_list_tail_slot_132,
              "the command-list vtable must cover [vtable+0x420]");

struct XsCommandListProxy {
    void** vtable;             // +0  COM vtable pointer seen by the caller.
    volatile LONG references;  // +8  proxy IUnknown reference count.
    void* real_list;           // +16 owned desktop ID3D12GraphicsCommandList.
    ProxyDevice* device_proxy; // +24 owning device proxy returned by GetDevice.
    void* thunk_memory;        // executable thunk block.
    void** vtable_memory;      // backing storage for `vtable`.
    bool replacement_active;   // the replacement root signature is currently bound.
    bool logged_root_constants; // diagnostic: first root-constant payload has been logged.
    ID3D12RootSignature* requested_root_signature; // last non-replacement root signature.
};

void destroy_command_list_proxy(XsCommandListProxy* proxy)
{
    if (proxy->real_list) static_cast<ID3D12GraphicsCommandList*>(proxy->real_list)->Release();
    if (proxy->thunk_memory) VirtualFree(proxy->thunk_memory, 0, MEM_RELEASE);
    delete[] proxy->vtable_memory;
    delete proxy;
}

ULONG WINAPI command_list_add_ref(XsCommandListProxy* proxy)
{
    return static_cast<ULONG>(InterlockedIncrement(&proxy->references));
}

ULONG WINAPI command_list_release(XsCommandListProxy* proxy)
{
    const LONG remaining = InterlockedDecrement(&proxy->references);
    if (remaining == 0) destroy_command_list_proxy(proxy);
    return static_cast<ULONG>(remaining);
}

HRESULT WINAPI command_list_query_interface(XsCommandListProxy* proxy, REFIID iid, void** out)
{
    if (!out) return E_POINTER;
    *out = nullptr;
    bool supported = IsEqualIID(iid, __uuidof(IUnknown)) ||
                     IsEqualIID(iid, __uuidof(ID3D12GraphicsCommandList)) ||
                     IsEqualIID(iid, xbox_command_list_iid);
#if defined(__ID3D12GraphicsCommandList6_INTERFACE_DEFINED__)
    supported = supported || IsEqualIID(iid, __uuidof(ID3D12GraphicsCommandList6));
#endif
    if (!supported) return E_NOINTERFACE;
    command_list_add_ref(proxy);
    *out = proxy;
    return S_OK;
}

HRESULT WINAPI command_list_get_device(XsCommandListProxy* proxy, REFIID iid, void** out)
{
    if (!proxy || !proxy->device_proxy) return E_FAIL;
    return proxy_query_interface(proxy->device_proxy, iid, out);
}

// Tail-called by a command-list stub. RDX holds the slot number (overwriting the original second
// argument is safe for these unforwarded slots); RCX is the caller's `this`, or for a hidden
// return buffer method the buffer itself. The buffer is never dereferenced.
HRESULT WINAPI command_list_unimplemented(XsCommandListProxy* self, std::uintptr_t slot)
{
    if (slot == command_list_tail_slot_131 || slot == command_list_tail_slot_132) {
        char line[160];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: command-list tail slot %llu called (self=%p) -> S_OK\n",
                      static_cast<unsigned long long>(slot), static_cast<void*>(self));
        write_log(line);
        return S_OK;
    }
    char line[160];
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: xbox command-list slot %llu called (self=%p) -> E_NOTIMPL\n",
                  static_cast<unsigned long long>(slot), static_cast<void*>(self));
    write_log(line);
    return E_NOTIMPL;
}

// Slot 25: forward SetPipelineState and keep the list's replacement state coherent. If the
// replacement PSO is selected after the title already bound its own root signature, re-apply the
// desktop replacement root signature; if the list leaves the replacement PSO, restore the title's
// last requested root signature.
void WINAPI command_list_set_pipeline_state(XsCommandListProxy* proxy, ID3D12PipelineState* pso)
{
    auto* real = static_cast<ID3D12GraphicsCommandList*>(proxy->real_list);
    real->SetPipelineState(pso);

    ProxyDevice* device = proxy->device_proxy;
    const bool replacement_pso =
        device && device->replacement_pso && pso == device->replacement_pso;
    if (replacement_pso && device->replacement_root_signature) {
        real->SetComputeRootSignature(device->replacement_root_signature);
        proxy->replacement_active = true;
        char line[192];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: command-list %p set replacement PSO %p -> root signature "
                      "substituted\n",
                      static_cast<void*>(proxy), static_cast<void*>(pso));
        write_log(line);
    } else if (proxy->replacement_active) {
        real->SetComputeRootSignature(proxy->requested_root_signature);
        proxy->replacement_active = false;
        char line[192];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: command-list %p left replacement PSO (pso=%p) -> restored "
                      "root %p\n",
                      static_cast<void*>(proxy), static_cast<void*>(pso),
                      static_cast<void*>(proxy->requested_root_signature));
        write_log(line);
    }
}

// Slot 29: substitute the shim-owned root signature when the title binds the root signature that
// was recorded for the replacement PSO. A previously bound replacement root signature is also
// accepted. Everything else is forwarded unchanged and clears the replacement state.
void WINAPI command_list_set_compute_root_signature(XsCommandListProxy* proxy,
                                                    ID3D12RootSignature* root_signature)
{
    auto* real = static_cast<ID3D12GraphicsCommandList*>(proxy->real_list);
    ProxyDevice* device = proxy->device_proxy;
    const bool is_our_root = device && root_signature == device->replacement_root_signature;
    const bool is_game_root =
        device && root_signature && root_signature == device->replacement_game_root_signature;
    const bool null_for_replacement =
        !root_signature && device && device->replacement_pso &&
        device->replacement_game_root_signature == nullptr;

    ID3D12RootSignature* effective = root_signature;
    if (device && device->replacement_root_signature && (is_game_root || null_for_replacement)) {
        effective = device->replacement_root_signature;
        proxy->replacement_active = true;
        proxy->requested_root_signature = root_signature;
        char line[224];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: command-list %p root %p -> replacement root %p (SRV t0/UAV u0)\n",
                      static_cast<void*>(proxy), static_cast<void*>(root_signature),
                      static_cast<void*>(effective));
        write_log(line);
    } else {
        proxy->replacement_active = is_our_root;
        if (!is_our_root) proxy->requested_root_signature = root_signature;
    }
    real->SetComputeRootSignature(effective);
}

// Slot 41: when the replacement binding is active, parameter 1 must reference the shim-owned dummy
// UAV so the replacement shader writes into shim memory. The title's own address/index is ignored.
// Otherwise the desktop call is forwarded unchanged.
void WINAPI command_list_set_compute_root_uav(XsCommandListProxy* proxy, UINT root_parameter_index,
                                              D3D12_GPU_VIRTUAL_ADDRESS buffer_location)
{
    auto* real = static_cast<ID3D12GraphicsCommandList*>(proxy->real_list);
    ProxyDevice* device = proxy->device_proxy;
    if (proxy->replacement_active && device && device->replacement_uav) {
        const D3D12_GPU_VIRTUAL_ADDRESS dummy = device->replacement_uav->GetGPUVirtualAddress();
        real->SetComputeRootUnorderedAccessView(1, dummy);
        char line[224];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: command-list %p UAV param %u addr 0x%llx -> dummy param 1 addr "
                      "0x%llx\n",
                      static_cast<void*>(proxy), static_cast<unsigned>(root_parameter_index),
                      static_cast<unsigned long long>(buffer_location),
                      static_cast<unsigned long long>(dummy));
        write_log(line);
    } else {
        real->SetComputeRootUnorderedAccessView(root_parameter_index, buffer_location);
    }
}

// Slot 40: SetComputeRoot32BitConstants. Forwarded unchanged, but the first call per list logs the
// payload so the console BVH base address carried in the L1 constant block is observable. This is
// diagnostic only and does not alter the constants.
void WINAPI command_list_set_root_constants(XsCommandListProxy* proxy, UINT root_parameter_index,
                                            UINT count, const void* data, UINT dest_offset)
{
    if (!proxy || !proxy->real_list) return;
    auto* real = static_cast<ID3D12GraphicsCommandList*>(proxy->real_list);
    if (data && count && !proxy->logged_root_constants) {
        proxy->logged_root_constants = true;
        const auto* words = static_cast<const std::uint32_t*>(data);
        const UINT shown = count < 8 ? count : 8;
        char line[256];
        int used = std::snprintf(line, sizeof(line),
                                 "d3d12_xs: root constants param=%u count=%u offset=%u first=",
                                 static_cast<unsigned>(root_parameter_index), static_cast<unsigned>(count),
                                 static_cast<unsigned>(dest_offset));
        for (UINT index = 0; index < shown && used > 0 && static_cast<std::size_t>(used) < sizeof(line);
             ++index) {
            used += std::snprintf(line + used, sizeof(line) - static_cast<std::size_t>(used),
                                  "%08x ", words[index]);
            if (used < 0) break;
        }
        write_log(line);
        write_log("\n");
    }
    real->SetComputeRoot32BitConstants(root_parameter_index, count, data, dest_offset);
}

// Prefer the newest desktop list interface the SDK exposes, then fall back to the base one.
HRESULT create_real_command_list(ID3D12Device* device, UINT node_mask, D3D12_COMMAND_LIST_TYPE type,
                                 ID3D12CommandAllocator* allocator,
                                 ID3D12PipelineState* initial_pso, void** out)
{
#if defined(__ID3D12GraphicsCommandList6_INTERFACE_DEFINED__)
    const HRESULT newer = device->CreateCommandList(node_mask, type, allocator, initial_pso,
                                                    __uuidof(ID3D12GraphicsCommandList6), out);
    if (SUCCEEDED(newer)) return newer;
    *out = nullptr;
#endif
    return device->CreateCommandList(node_mask, type, allocator, initial_pso,
                                     __uuidof(ID3D12GraphicsCommandList), out);
}

XsCommandListProxy* create_command_list_proxy(void* real_list, ProxyDevice* device_proxy)
{
    auto* proxy = new (std::nothrow) XsCommandListProxy{};
    if (!proxy) return nullptr;

    proxy->vtable_memory = new (std::nothrow) void*[command_list_vtable_slots]{};
    if (!proxy->vtable_memory) {
        delete proxy;
        return nullptr;
    }

    auto* code = static_cast<std::uint8_t*>(VirtualAlloc(
        nullptr, command_list_thunk_block_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!code) {
        delete[] proxy->vtable_memory;
        delete proxy;
        return nullptr;
    }

    proxy->vtable = proxy->vtable_memory;
    proxy->vtable_memory[0] = reinterpret_cast<void*>(&command_list_query_interface);
    proxy->vtable_memory[1] = reinterpret_cast<void*>(&command_list_add_ref);
    proxy->vtable_memory[2] = reinterpret_cast<void*>(&command_list_release);

    std::uint8_t* cursor = code;
    for (std::size_t slot = command_list_forward_first; slot <= command_list_forward_last; ++slot) {
        void* thunk = cursor;
        cursor = emit_forward_thunk(
            cursor, static_cast<std::uint32_t>(offsetof(XsCommandListProxy, real_list)),
            static_cast<std::uint32_t>(slot), false);
        proxy->vtable_memory[slot] = thunk;
    }
    proxy->vtable_memory[7] = reinterpret_cast<void*>(&command_list_get_device);
    proxy->vtable_memory[command_list_set_pipeline_state_slot] =
        reinterpret_cast<void*>(&command_list_set_pipeline_state);
    proxy->vtable_memory[command_list_set_compute_root_signature_slot] =
        reinterpret_cast<void*>(&command_list_set_compute_root_signature);
    proxy->vtable_memory[command_list_set_compute_root_uav_slot] =
        reinterpret_cast<void*>(&command_list_set_compute_root_uav);
    proxy->vtable_memory[command_list_set_root_constants_slot] =
        reinterpret_cast<void*>(&command_list_set_root_constants);
    for (std::size_t slot = command_list_stub_first; slot < command_list_vtable_slots; ++slot) {
        void* stub = cursor;
        cursor = emit_xbox_stub(cursor, slot, reinterpret_cast<const void*>(&command_list_unimplemented));
        proxy->vtable_memory[slot] = stub;
    }

    if (cursor != code + command_list_thunk_block_bytes) {
        VirtualFree(code, 0, MEM_RELEASE);
        delete[] proxy->vtable_memory;
        delete proxy;
        return nullptr;
    }

    FlushInstructionCache(GetCurrentProcess(), code, command_list_thunk_block_bytes);
    DWORD previous_protection = 0;
    if (!VirtualProtect(code, command_list_thunk_block_bytes, PAGE_EXECUTE_READ,
                        &previous_protection)) {
        VirtualFree(code, 0, MEM_RELEASE);
        delete[] proxy->vtable_memory;
        delete proxy;
        return nullptr;
    }

    proxy->thunk_memory = code;
    proxy->real_list = real_list;
    proxy->device_proxy = device_proxy;
    proxy->references = 1; // the caller's reference; one proxy per CreateCommandListX call
    return proxy;
}

// Xbox device vtable slot 73 (offset 0x248). Arguments 5 and 6 arrive on the stack under x64.
HRESULT WINAPI create_xbox_command_list(ProxyDevice* proxy, const XboxCommandListDesc* desc,
                                        void* allocator, void* initial_pso,
                                        const GUID* requested_iid, void** out)
{
    if (!out) return E_POINTER;
    *out = nullptr;
    if (!proxy || !proxy->real) return E_UNEXPECTED;

    const D3D12_COMMAND_LIST_TYPE type = desc
        ? static_cast<D3D12_COMMAND_LIST_TYPE>(desc->type)
        : D3D12_COMMAND_LIST_TYPE_DIRECT;
    const UINT node_mask = desc ? desc->node_mask : 1u;

    void* real_list = nullptr;
    const HRESULT create_hr = create_real_command_list(
        proxy->real, node_mask, type, static_cast<ID3D12CommandAllocator*>(allocator),
        static_cast<ID3D12PipelineState*>(initial_pso), &real_list);
    if (FAILED(create_hr) || !real_list) {
        char line[192];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: CreateCommandListX type=%u node=%u -> 0x%08lx\n",
                      static_cast<unsigned>(type), static_cast<unsigned>(node_mask),
                      static_cast<unsigned long>(create_hr));
        write_log(line);
        *out = nullptr;
        return FAILED(create_hr) ? create_hr : E_FAIL;
    }

    XsCommandListProxy* list_proxy = create_command_list_proxy(real_list, proxy);
    if (!list_proxy) {
        static_cast<ID3D12GraphicsCommandList*>(real_list)->Release();
        write_log("d3d12_xs: command-list proxy allocation failed -> E_OUTOFMEMORY\n");
        *out = nullptr;
        return E_OUTOFMEMORY;
    }

    char iid_text[64];
    if (requested_iid) {
        format_iid(*requested_iid, iid_text, sizeof(iid_text));
    } else {
        std::snprintf(iid_text, sizeof(iid_text), "<null>");
    }
    char line[256];
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: slot 73 CreateCommandListX device=%p desc=%p type=%u node=%u iid=%s "
                  "real=%p proxy=%p\n",
                  static_cast<void*>(proxy), static_cast<const void*>(desc),
                  static_cast<unsigned>(type), static_cast<unsigned>(node_mask), iid_text,
                  real_list, static_cast<void*>(list_proxy));
    write_log(line);

    *out = list_proxy;
    return S_OK;
}

// Observed title call at 0x2478de4: Xbox device slot 0x278 (79) with scalar arguments and no out
// pointer, HRESULT checked only for >= 0. This is a desktop-safe no-op until the Xbox method is
// measured; it is likely a frame/interval configuration call.
constexpr std::size_t slot78_slot = 78;
HRESULT WINAPI slot78_noop(ProxyDevice*) { return S_OK; }

constexpr std::size_t set_frame_interval_x_slot = 79;

HRESULT WINAPI set_frame_interval_x(ProxyDevice* proxy, std::uint32_t interval, std::uintptr_t,
                                    std::uintptr_t, std::uintptr_t)
{
    char line[160];
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: xbox vtable slot 79 called (device=%p interval=%u) -> S_OK\n",
                  static_cast<void*>(proxy), static_cast<unsigned>(interval));
    write_log(line);
    return S_OK;
}

// Observed post-map call at 0x1e8684c: Xbox device slot 0x428 (133), scalar/pointer arguments and
// no measured out parameter. Desktop has no equivalent frame-event setup, so log and succeed.
constexpr std::size_t configure_frame_event_slot = 133;

HRESULT WINAPI configure_frame_event(ProxyDevice*, std::uintptr_t, std::uintptr_t,
                                     std::uintptr_t, std::uintptr_t, std::uintptr_t,
                                     std::uintptr_t)
{
    return S_OK;
}

// The measured title calls GDK CreateCommandQueueX at offset 0x180 (slot 48), before the desktop
// Device1+ methods. Translate its Xbox queue descriptor to the desktop descriptor and use slot 8 of
// the real device. Only the Type field is measured; priority/flags/node are desktop defaults.
// Desktop D3D12 limits shader-visible CBV/SRV/UAV heaps to 1,000,000 descriptors. The measured
// title requests 0x130000 (1,245,184), which makes the desktop debug layer throw E_INVALIDARG.
// Clamp only this shader-visible view heap, create the real heap, and patch the title's expected
// pool base global (exe RVA 0x75df188) to the real heap's CPU start. The pool builder compares that
// base after creation; without the patch it hits its own debug break.
// Desktop descriptor-heap proxy. The console call site uses a C-style handle return (RAX) while the
// desktop heap's handle getters are sret-style; returning the raw desktop heap made the getter write
// through the title's second argument. The proxy forwards handle getters in the title's ABI and
// exposes the real heap's CPU/GPU handle values.
struct DescriptorHeapProxy {
    void** vtable;              // +0
    volatile LONG references;   // +8
    ID3D12DescriptorHeap* real; // +16
    void** vtable_memory;       // +24
    bool use_legacy_base;       // +32 shader-visible pool reports the title's recorded base
};

void destroy_descriptor_heap_proxy(DescriptorHeapProxy* proxy)
{
    if (proxy->real) proxy->real->Release();
    delete[] proxy->vtable_memory;
    delete proxy;
}

ULONG WINAPI descriptor_heap_add_ref(DescriptorHeapProxy* proxy)
{
    return static_cast<ULONG>(InterlockedIncrement(&proxy->references));
}

ULONG WINAPI descriptor_heap_release(DescriptorHeapProxy* proxy)
{
    const LONG remaining = InterlockedDecrement(&proxy->references);
    if (remaining == 0) destroy_descriptor_heap_proxy(proxy);
    return static_cast<ULONG>(remaining);
}

HRESULT WINAPI descriptor_heap_query_interface(DescriptorHeapProxy* proxy, REFIID iid, void** out)
{
    if (!out) return E_POINTER;
    *out = nullptr;
    if (IsEqualIID(iid, __uuidof(IUnknown)) || IsEqualIID(iid, __uuidof(ID3D12DescriptorHeap)) ||
        IsEqualIID(iid, __uuidof(ID3D12Pageable)) || IsEqualIID(iid, __uuidof(ID3D12DeviceChild))) {
        descriptor_heap_add_ref(proxy);
        *out = proxy;
        return S_OK;
    }
    return E_NOINTERFACE;
}

// The title derives descriptor handles from this start and later compares it against the legacy XMem
// pool base it recorded at game RVA 0x1e864ac. Reporting the desktop heap address makes that check
// fail; reporting the recorded base keeps the title's own bookkeeping coherent. The GPU handle is
// offset by the same delta so CPU/GPU pairs stay consistent.
constexpr std::uintptr_t legacy_descriptor_pool_base_rva = 0x75DF188;

std::uintptr_t legacy_pool_base()
{
    HMODULE game = GetModuleHandleW(nullptr);
    if (!game) return 0;
    const auto* slot = reinterpret_cast<const std::uintptr_t*>(
        reinterpret_cast<const unsigned char*>(game) + legacy_descriptor_pool_base_rva);
    return *slot;
}

D3D12_CPU_DESCRIPTOR_HANDLE WINAPI descriptor_heap_get_cpu(DescriptorHeapProxy* proxy)
{
    const D3D12_CPU_DESCRIPTOR_HANDLE real = proxy->real->GetCPUDescriptorHandleForHeapStart();
    const std::uintptr_t legacy = legacy_pool_base();
    if (proxy->use_legacy_base && legacy) return D3D12_CPU_DESCRIPTOR_HANDLE{legacy};
    return real;
}

D3D12_GPU_DESCRIPTOR_HANDLE WINAPI descriptor_heap_get_gpu(DescriptorHeapProxy* proxy)
{
    const D3D12_GPU_DESCRIPTOR_HANDLE real = proxy->real->GetGPUDescriptorHandleForHeapStart();
    const std::uintptr_t legacy = legacy_pool_base();
    const std::uintptr_t cpu = proxy->real->GetCPUDescriptorHandleForHeapStart().ptr;
    if (proxy->use_legacy_base && legacy && cpu)
        return D3D12_GPU_DESCRIPTOR_HANDLE{real.ptr + (legacy - cpu)};
    return real;
}

HRESULT WINAPI descriptor_heap_unimplemented(DescriptorHeapProxy*)
{
    return E_NOTIMPL;
}

DescriptorHeapProxy* create_descriptor_heap_proxy(ID3D12DescriptorHeap* real, bool use_legacy_base)
{
    auto* proxy = new (std::nothrow) DescriptorHeapProxy{};
    if (!proxy) return nullptr;
    proxy->vtable_memory = new (std::nothrow) void*[16]{};
    if (!proxy->vtable_memory) {
        delete proxy;
        return nullptr;
    }
    proxy->vtable = proxy->vtable_memory;
    proxy->references = 1;
    proxy->real = real;
    proxy->vtable_memory[0] = reinterpret_cast<void*>(&descriptor_heap_query_interface);
    proxy->vtable_memory[1] = reinterpret_cast<void*>(&descriptor_heap_add_ref);
    proxy->vtable_memory[2] = reinterpret_cast<void*>(&descriptor_heap_release);
    for (std::size_t slot = 3; slot < 16; ++slot) {
        proxy->vtable_memory[slot] = reinterpret_cast<void*>(&descriptor_heap_unimplemented);
    }
    proxy->use_legacy_base = use_legacy_base;
    proxy->vtable_memory[9] = reinterpret_cast<void*>(&descriptor_heap_get_cpu);
    proxy->vtable_memory[10] = reinterpret_cast<void*>(&descriptor_heap_get_gpu);
    return proxy;
}

// Measured at game RVA 0x247954e..0x2479646: the bring-up routine asks the device for command
// signatures through slot 41 (0x148). The console indirect-argument type 0x69 (105) is rejected by
// desktop D3D12 with E_INVALIDARG; its byte stride of 12 (3 x UINT) matches a dispatch signature, so
// translate it to D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH. DRAW (0) and DRAW_INDEXED (1) pass through.
constexpr std::size_t create_command_signature_slot = 41;
constexpr std::uint32_t console_indirect_dispatch_type = 0x69u;
constexpr UINT max_command_signature_args = 8;

HRESULT WINAPI create_command_signature_x(ProxyDevice* proxy,
                                          const D3D12_COMMAND_SIGNATURE_DESC* desc,
                                          ID3D12RootSignature* root_signature, REFIID iid,
                                          void** signature)
{
    if (!proxy || !proxy->real) return E_UNEXPECTED;
    if (!desc || !signature) return E_POINTER;
    *signature = nullptr;

    D3D12_COMMAND_SIGNATURE_DESC copy = *desc;
    if (!copy.NodeMask) copy.NodeMask = 1;

    D3D12_INDIRECT_ARGUMENT_DESC translated[max_command_signature_args]{};
    if (copy.NumArgumentDescs && copy.pArgumentDescs) {
        if (copy.NumArgumentDescs > max_command_signature_args) {
            write_log("d3d12_xs: CreateCommandSignatureX too many argument descs -> E_INVALIDARG\n");
            return E_INVALIDARG;
        }
        for (UINT index = 0; index < copy.NumArgumentDescs; ++index) {
            translated[index] = copy.pArgumentDescs[index];
            if (static_cast<std::uint32_t>(translated[index].Type) ==
                console_indirect_dispatch_type) {
                translated[index].Type = D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH;
            }
        }
        copy.pArgumentDescs = translated;
    }

    const HRESULT result =
        proxy->real->CreateCommandSignature(&copy, root_signature, iid, signature);
    char line[192];
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: CreateCommandSignatureX stride=%u args=%u -> 0x%08lx\n",
                  static_cast<unsigned>(copy.ByteStride), static_cast<unsigned>(copy.NumArgumentDescs),
                  static_cast<unsigned long>(result));
    write_log(line);
    return result;
}

constexpr std::size_t create_descriptor_heap_slot = 14;
constexpr UINT desktop_shader_visible_limit = 1'000'000;

// The title caches the console descriptor stride before it builds the view pools. On Scarlett that
// cached value is 0xd8 while the desktop CBV/SRV/UAV increment is 0x20. The pool builder asks the
// real device for the increment, but the reservation that is subtracted from the clamped logical
// pool end (exe RVA 0x75df168) was precomputed with the cached value. With the desktop 1,000,000
// descriptor clamp, that left only 0x384800 bytes, so the legacy view allocator initialization
// (0x50000 descriptors, exe RVAs 0xa94393c/0xa943940) failed and the first view helper received a
// stale stack value (0xb) as its CPU descriptor handle. Sync the cached stride with the real
// device increment so the reservation and the pool use the same byte size. Measured game RVAs:
// cached increment 0xa943914, reserved bytes 0x75df168.
constexpr std::uintptr_t cached_descriptor_increment_rva = 0xA943914;

void sync_cached_descriptor_increment(ID3D12Device* real)
{
    HMODULE game = GetModuleHandleW(nullptr);
    if (!game || !real) return;
    const UINT increment =
        real->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    auto* slot = reinterpret_cast<std::uint32_t*>(
        reinterpret_cast<unsigned char*>(game) + cached_descriptor_increment_rva);
    const std::uint32_t previous = *slot;
    if (previous == increment) return;
    DWORD old_protection = 0;
    if (VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_protection)) {
        *slot = increment;
        VirtualProtect(slot, sizeof(*slot), old_protection, &old_protection);
        char line[192];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: cached descriptor increment 0x%x -> 0x%x\n",
                      static_cast<unsigned>(previous), static_cast<unsigned>(increment));
        write_log(line);
    }
}


HRESULT WINAPI create_descriptor_heap(ProxyDevice* proxy, const D3D12_DESCRIPTOR_HEAP_DESC* desc,
                                      REFIID iid, void** heap)
{
    if (!proxy || !proxy->real) return E_UNEXPECTED;
    if (!desc || !heap) return E_POINTER;
    *heap = nullptr;
    sync_cached_descriptor_increment(proxy->real);
    D3D12_DESCRIPTOR_HEAP_DESC copy = *desc;
    const bool clamp = (copy.Flags & D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE) &&
                       copy.NumDescriptors > desktop_shader_visible_limit;
    if (clamp) copy.NumDescriptors = desktop_shader_visible_limit;
    ID3D12DescriptorHeap* real_heap = nullptr;
    const HRESULT result = proxy->real->CreateDescriptorHeap(
        &copy, iid, reinterpret_cast<void**>(&real_heap));
    if (FAILED(result) || !real_heap) {
        char line[192];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: CreateDescriptorHeap type=%u num=%u flags=%u -> 0x%08lx\n",
                      static_cast<unsigned>(copy.Type), static_cast<unsigned>(copy.NumDescriptors),
                      static_cast<unsigned>(copy.Flags), static_cast<unsigned long>(result));
        write_log(line);
        return FAILED(result) ? result : E_FAIL;
    }
    if (clamp) {
        char line[192];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: clamped descriptor heap %u -> %u\n",
                      static_cast<unsigned>(desc->NumDescriptors),
                      static_cast<unsigned>(copy.NumDescriptors));
        write_log(line);
    }
    // The title's descriptor bump allocator writes its descriptor array into the pool base it
    // recorded at game RVA 0x1e864ac. That range is only reserved (PAGE_NOACCESS) by the XMem shim,
    // so make it writable for the bookkeeping the title performs there. Measured: without this the
    // first `mov dword ptr [pool_base], n` faults.
    if ((copy.Flags & D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE) != 0) {
        const std::uintptr_t legacy = legacy_pool_base();
        const UINT increment = proxy->real->GetDescriptorHandleIncrementSize(copy.Type);
        if (legacy && increment) {
            const SIZE_T bytes = static_cast<SIZE_T>(copy.NumDescriptors) * increment;
            // The legacy base is one segment of the title's XMem pool, not the whole descriptor
            // array, so commit in 64 KiB pages and stop at the first hole. The title's writes stay
            // inside the committed part.
            SIZE_T committed_bytes = 0;
            constexpr SIZE_T page = 64 * 1024;
            while (committed_bytes < bytes) {
                const SIZE_T step = bytes - committed_bytes < page ? bytes - committed_bytes : page;
                if (!VirtualAlloc(reinterpret_cast<void*>(legacy + committed_bytes), step, MEM_COMMIT,
                                  PAGE_READWRITE))
                    break;
                committed_bytes += step;
            }
            char line[224];
            std::snprintf(line, sizeof(line),
                          "d3d12_xs: legacy descriptor pool commit base=0x%llx requested=%llu "
                          "committed=%llu\n",
                          static_cast<unsigned long long>(legacy),
                          static_cast<unsigned long long>(bytes),
                          static_cast<unsigned long long>(committed_bytes));
            write_log(line);
        }
    }

    DescriptorHeapProxy* wrapper = create_descriptor_heap_proxy(real_heap, (copy.Flags & D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE) != 0);
    if (!wrapper) {
        real_heap->Release();
        return E_OUTOFMEMORY;
    }
    *heap = wrapper;
    return result;
}

constexpr std::size_t create_command_queue_x_slot = 48;

HRESULT WINAPI create_command_queue_x(ProxyDevice* proxy, const void* desc, REFIID iid, void** queue)
{
    if (!proxy || !proxy->real) return E_UNEXPECTED;
    if (!queue) return E_POINTER;
    *queue = nullptr;
    D3D12_COMMAND_QUEUE_DESC translated{};
    if (desc) {
        translated.Type = static_cast<D3D12_COMMAND_LIST_TYPE>(
            *static_cast<const std::uint32_t*>(desc));
    }
    translated.Priority = D3D12_COMMAND_QUEUE_PRIORITY_NORMAL;
    translated.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
    translated.NodeMask = 1;
    const HRESULT result = proxy->real->CreateCommandQueue(&translated, iid, queue);
    if (FAILED(result)) {
        char line[192];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: CreateCommandQueueX type=%u -> 0x%08lx\n",
                      static_cast<unsigned>(translated.Type), static_cast<unsigned long>(result));
        write_log(line);
    }
    return result;
}

// Adopts the caller's reference on `real`; returns nullptr without touching it on failure.
// Measured Xbox committed-resource creation at 0x193e1b4 (device slot 127 / 0x3f8). The console
// entry inserts three extra arguments after the desktop clear value, then supplies IID and out.
// RCX=proxy, RDX=heap properties, R8D=heap flags, R9=resource desc, stack: initial state, clear
// value, three console-only args, REFIID, out. Translate to desktop CreateCommittedResource.
// Xbox device slot 61 is not desktop ID3D12Device5::CreateMetaCommand: the measured call passes an
// 8-dword descriptor {0,1,1,2,2,0,1,1} in the second argument, which is not a REFCLSID, and the
// remaining arguments do not match that signature either. Two earlier versions of this handler
// faulted by writing through a misinterpreted out pointer, so this stays fail-closed and never
// dereferences anything.
constexpr std::size_t create_meta_command_slot = 61;

HRESULT WINAPI create_meta_command(ProxyDevice*, const void*, std::uintptr_t, std::uintptr_t,
                                   REFIID, void**)
{
    static volatile LONG logged = 0;
    if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
        write_log("d3d12_xs: slot61 console meta command unsupported -> E_NOTIMPL\n");
    }
    return E_NOTIMPL;
}

constexpr std::size_t create_committed_resource_x_slot = 127;

HRESULT WINAPI create_committed_resource_x(
    ProxyDevice* proxy, const D3D12_HEAP_PROPERTIES* heap_properties, D3D12_HEAP_FLAGS heap_flags,
    const D3D12_RESOURCE_DESC* resource_desc, D3D12_RESOURCE_STATES initial_state,
    const D3D12_CLEAR_VALUE* clear_value, std::uintptr_t, std::uintptr_t, std::uintptr_t,
    REFIID iid, void** resource)
{
    if (!proxy || !proxy->real) return E_UNEXPECTED;
    if (!heap_properties || !resource_desc || !resource) return E_INVALIDARG;
    *resource = nullptr;
    D3D12_RESOURCE_DESC safe_desc = *resource_desc;
    constexpr D3D12_RESOURCE_FLAGS allowed_flags =
        static_cast<D3D12_RESOURCE_FLAGS>(D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET |
                                          D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL |
                                          D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS |
                                          D3D12_RESOURCE_FLAG_ALLOW_SIMULTANEOUS_ACCESS);
    safe_desc.Flags = static_cast<D3D12_RESOURCE_FLAGS>(safe_desc.Flags & allowed_flags);
    const HRESULT result = proxy->real->CreateCommittedResource(
        heap_properties, D3D12_HEAP_FLAG_NONE, &safe_desc, D3D12_RESOURCE_STATE_COMMON,
        clear_value, iid, resource);
    if (FAILED(result)) {
        char line[192];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: CreateCommittedResourceX dim=%u w=%llu h=%u flags=%u -> "
                      "0x%08lx\n",
                      static_cast<unsigned>(safe_desc.Dimension),
                      static_cast<unsigned long long>(safe_desc.Width),
                      static_cast<unsigned>(safe_desc.Height),
                      static_cast<unsigned>(heap_flags), static_cast<unsigned long>(result));
        write_log(line);
    }
    return result;
}

// Desktop slot 62 is ID3D12Device5::CreateStateObject. The bundled BVH builder reached this slot
// through the device proxy and threw E_NOTIMPL when the generic Xbox stub answered. DXR is available
// on the real device (tier 12), so forward the state-object request.
constexpr std::size_t create_state_object_slot = 62;

HRESULT WINAPI create_state_object(ProxyDevice* proxy, const D3D12_STATE_OBJECT_DESC* desc,
                                   REFIID iid, void** state_object)
{
    if (!proxy || !proxy->real) return E_UNEXPECTED;
    if (!state_object) return E_POINTER;
    *state_object = nullptr;
    ID3D12Device5* device5 = nullptr;
    HRESULT result = proxy->real->QueryInterface(
        __uuidof(ID3D12Device5), reinterpret_cast<void**>(&device5));
    if (SUCCEEDED(result) && device5) {
        result = device5->CreateStateObject(desc, iid, state_object);
        device5->Release();
    }
    char line[192];
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: CreateStateObject type=%u subobjects=%u -> 0x%08lx\n",
                  desc ? static_cast<unsigned>(desc->Type) : 0u,
                  desc ? static_cast<unsigned>(desc->NumSubobjects) : 0u,
                  static_cast<unsigned long>(result));
    write_log(line);
    return result;
}

// Observed Xbox view creation at device slot 70 (0x230): RDX = CPU handle pointer,
// R8 = D3D12_SHADER_RESOURCE_VIEW_DESC*, R9 = ID3D12Resource*. Translate to desktop slot 18.
constexpr std::size_t create_shader_resource_view_x_slot = 70;

// Slot 70 (offset 0x230) is the console view-creation entry used by the descriptor wrapper at game
// RVA 0x4ecc800. Its measured call is (device, source, desc, destination). The desktop equivalent
// needs a real ID3D12Resource plus a view description, and the console payload layout is not yet
// established, so the handler records the first call's arguments and stays inert. Diagnostic only.
HRESULT WINAPI create_shader_resource_view_x(ProxyDevice* proxy, const void* source,
                                             const void* desc, void* destination)
{
    static volatile LONG logged = 0;
    if (proxy && proxy->real && InterlockedCompareExchange(&logged, 1, 0) == 0) {
        char line[256];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: slot70 view source=%p desc=%p dest=%p\n",
                      const_cast<void*>(source), const_cast<void*>(desc), destination);
        write_log(line);
        if (desc) {
            const auto* bytes = static_cast<const unsigned char*>(desc);
            std::snprintf(line, sizeof(line),
                          "d3d12_xs: slot70 desc %02x%02x%02x%02x %02x%02x%02x%02x "
                          "%02x%02x%02x%02x %02x%02x%02x%02x\n",
                          bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                          bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
                          bytes[14], bytes[15]);
            write_log(line);
        }
        if (source) {
            std::uintptr_t vtable = 0;
            std::memcpy(&vtable, source, sizeof(vtable));
            std::snprintf(line, sizeof(line), "d3d12_xs: slot70 source vtable=0x%llx\n",
                          static_cast<unsigned long long>(vtable));
            write_log(line);
        }
    }
    return S_OK;
}

// Xbox slot 62 is measured as compute-PSO creation (root-signature pointer, DXBC blob, IID on the
// stack, out on the stack), not desktop ID3D12Device5::CreateStateObject. The title's blob is Xbox
// DXIL, so only the measured InitPartitionedHeaders container is replaced by a local source-built
// shader. Every other PSO keeps the source-built no-op SM5 compute shader, and the replacement is
// also skipped when its file, desktop root signature or dummy UAV is unavailable. The replacement
// PSO is built against a shim-owned desktop root signature instead of desc->pRootSignature; the
// command-list proxy substitutes that root signature and the dummy UAV when the PSO is dispatched.
constexpr std::size_t create_compute_pipeline_state_x_slot = 62;

struct noop_compute_shader {
    ID3DBlob* blob = nullptr;
    HRESULT result = E_FAIL;
};

const noop_compute_shader& noop_compute_shader_blob()
{
    static const noop_compute_shader shader = [] {
        using d3dcompile_fn = HRESULT(WINAPI*)(LPCVOID, SIZE_T, LPCSTR, const void*, void*, LPCSTR,
                                              LPCSTR, UINT, UINT, ID3DBlob**, ID3DBlob**);
        noop_compute_shader value{};
        HMODULE compiler = LoadLibraryW(L"d3dcompiler_47.dll");
        if (!compiler) return value;
        const auto compile = reinterpret_cast<d3dcompile_fn>(
            GetProcAddress(compiler, "D3DCompile"));
        if (!compile) return value;
        constexpr char source[] =
            "[numthreads(1,1,1)] void main(uint3 id : SV_DispatchThreadID) {}";
        ID3DBlob* errors = nullptr;
        value.result = compile(source, sizeof(source) - 1, "noop_compute", nullptr, nullptr,
                               "main", "cs_5_0", 0, 0, &value.blob, &errors);
        if (errors) errors->Release();
        if (FAILED(value.result)) {
            if (value.blob) {
                value.blob->Release();
                value.blob = nullptr;
            }
        }
        return value;
    }();
    return shader;
}

// ---------------------------------------------------------------------------------------------
// InitPartitionedHeaders replacement registry.
//
// Detection uses the measured container length and an FNV-1a 64-bit hash over every byte of
// desc->CS, not over a DXIL sub-chunk:
//   container length = 0x1410
//   FNV-1a 64        = 0x1e3c95fd4232f377
// The hash was taken from the XboxBvhBuilder.dll DXBC container at RVA 0xc96b0. The replacement
// bytes are never embedded in this file. They are read once from BVH_SHADER_DIR when that variable
// is set, otherwise from the directory containing d3d12_xs.dll, and then cached for the process.
// ---------------------------------------------------------------------------------------------
struct replacement_shader_entry {
    SIZE_T length;
    std::uint64_t fnv1a64;
    const wchar_t* file_name;
    const char* label;
};

// Console shader containers that have a source-built desktop replacement. The key is the container
// byte length plus the FNV-1a 64 of the container bytes; the replacement file lives in
// BVH_SHADER_DIR (or next to d3d12_xs.dll) and is never shipped in the repository.
constexpr replacement_shader_entry replacement_shaders[] = {
    {0x1410, 0x1e3c95fd4232f377ull, L"init_partitioned_headers.signed.dxil",
     "InitPartitionedHeaders"},
    {0x1488, 0x40891c36f2e1e8aaull, L"init_headers.signed.dxil", "InitHeaders"},
    {0x1118, 0x244fbfb4d63958bfull, L"pt_begin_pass.signed.dxil", "PT_BeginPass"},
    // Containers that use no xbox.* intrinsics: retarget + sign only, no source rewrite.
    {0x1134, 0x9e3107c7a215e9e9ull, L"copy_and_compact_bvh.signed.dxil", "CopyAndCompactBVH"},
    {0x1194, 0x999c5fa5f4f5d83cull, L"decompress_header.signed.dxil", "DecompressHeader"},
    {0x10d0, 0x49491fe19cf20422ull, L"reset_kdop.signed.dxil", "ResetKDOP"},
    {0x5e60, 0x4e7a3ffdba738043ull, L"pt_construct_bvh4.signed.dxil", "PT_ConstructBVH4"},
    {0x0fec, 0xab39445dd0120e52ull, L"radix_reset.signed.dxil", "RadixReset"},
    {0x10e8, 0xef0d378acaeb428eull, L"copy_counters.signed.dxil", "CopyCounters"},
    {0x1004, 0xf7b2f1886df21ee6ull, L"reset_to_index_buffer.signed.dxil", "ResetToIndexBuffer"},
    {0x126c, 0x83225f64b531e807ull, L"copy_for_bvh_update.signed.dxil", "CopyForBVHUpdate"},
    {0x0fe8, 0x20c629c82e9687b4ull, L"reset_counter_values.signed.dxil", "ResetCounterValues"},
};
constexpr std::size_t replacement_shader_count =
    sizeof(replacement_shaders) / sizeof(replacement_shaders[0]);
constexpr wchar_t replacement_shader_dir_variable[] = L"BVH_SHADER_DIR";
constexpr DWORD max_replacement_shader_bytes = 64u * 1024u * 1024u;
constexpr DWORD replacement_path_capacity = 32768;

std::uint64_t fnv1a64(const void* data, SIZE_T size)
{
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint64_t hash = 0xcbf29ce484222325ull;
    for (SIZE_T index = 0; index < size; ++index) {
        hash ^= bytes[index];
        hash *= 0x100000001b3ull;
    }
    return hash;
}

// Returns the registry index of a shader with a desktop replacement, or -1.
int find_replacement_shader(const D3D12_SHADER_BYTECODE& shader)
{
    if (shader.pShaderBytecode == nullptr) return -1;
    bool length_known = false;
    for (std::size_t index = 0; index < replacement_shader_count; ++index) {
        if (replacement_shaders[index].length == shader.BytecodeLength) {
            length_known = true;
            break;
        }
    }
    if (!length_known) return -1;
    const std::uint64_t hash = fnv1a64(shader.pShaderBytecode, shader.BytecodeLength);
    for (std::size_t index = 0; index < replacement_shader_count; ++index) {
        if (replacement_shaders[index].length == shader.BytecodeLength &&
            replacement_shaders[index].fnv1a64 == hash) {
            return static_cast<int>(index);
        }
    }
    return -1;
}

struct replacement_shader_cache {
    bool attempted = false;
    std::uint8_t* bytes = nullptr;
    SIZE_T size = 0;
};

replacement_shader_cache replacement_shader_slots[replacement_shader_count];
SRWLOCK replacement_shader_lock = SRWLOCK_INIT;

bool get_shim_directory(wchar_t* directory, DWORD capacity)
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&write_log), &module) ||
        !module) {
        return false;
    }
    const DWORD length = GetModuleFileNameW(module, directory, capacity);
    if (length == 0 || length >= capacity) return false;
    SIZE_T last_separator = static_cast<SIZE_T>(-1);
    for (SIZE_T index = 0; index < length; ++index) {
        if (directory[index] == L'\\' || directory[index] == L'/') last_separator = index;
    }
    if (last_separator == static_cast<SIZE_T>(-1)) return false;
    directory[last_separator] = L'\0';
    return true;
}

bool build_replacement_path(const wchar_t* directory, const wchar_t* file_name, wchar_t* path,
                            DWORD capacity)
{
    SIZE_T length = 0;
    while (directory[length] != L'\0') ++length;
    if (length == 0) return false;
    const bool needs_separator = directory[length - 1] != L'\\' && directory[length - 1] != L'/';
    return swprintf_s(path, capacity, needs_separator ? L"%s\\%s" : L"%s%s", directory, file_name) >
           0;
}

bool read_replacement_shader(const wchar_t* path, replacement_shader_cache& cache)
{
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        char line[160];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: BVH replacement shader unavailable (open error %lu) -> noop\n",
                      static_cast<unsigned long>(GetLastError()));
        write_log(line);
        return false;
    }
    LARGE_INTEGER file_size{};
    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart <= 0 ||
        file_size.QuadPart > static_cast<LONGLONG>(max_replacement_shader_bytes)) {
        CloseHandle(file);
        write_log("d3d12_xs: BVH replacement shader size rejected -> noop\n");
        return false;
    }
    const SIZE_T size = static_cast<SIZE_T>(file_size.QuadPart);
    auto* bytes = new (std::nothrow) std::uint8_t[size];
    if (!bytes) {
        CloseHandle(file);
        write_log("d3d12_xs: BVH replacement shader allocation failed -> noop\n");
        return false;
    }
    SIZE_T offset = 0;
    while (offset < size) {
        const SIZE_T remaining = size - offset;
        const DWORD request = static_cast<DWORD>(remaining > 0x7fffffffu ? 0x7fffffffu : remaining);
        DWORD read = 0;
        if (!ReadFile(file, bytes + offset, request, &read, nullptr) || read == 0) {
            delete[] bytes;
            CloseHandle(file);
            write_log("d3d12_xs: BVH replacement shader read failed -> noop\n");
            return false;
        }
        offset += read;
    }
    CloseHandle(file);
    cache.bytes = bytes;
    cache.size = size;
    char line[160];
    std::snprintf(line, sizeof(line), "d3d12_xs: BVH replacement shader loaded bytes=%llu\n",
                  static_cast<unsigned long long>(size));
    write_log(line);
    return true;
}

const replacement_shader_cache& replacement_shader_blob(int index)
{
    static const replacement_shader_cache empty{};
    if (index < 0 || static_cast<std::size_t>(index) >= replacement_shader_count) return empty;
    replacement_shader_cache& slot = replacement_shader_slots[index];
    AcquireSRWLockExclusive(&replacement_shader_lock);
    if (!slot.attempted) {
        slot.attempted = true;
        wchar_t directory[replacement_path_capacity];
        const DWORD env_length = GetEnvironmentVariableW(
            replacement_shader_dir_variable, directory, replacement_path_capacity);
        bool have_directory = env_length > 0 && env_length < replacement_path_capacity;
        if (!have_directory) {
            if (env_length == 0) {
                have_directory = get_shim_directory(directory, replacement_path_capacity);
            } else {
                write_log("d3d12_xs: BVH_SHADER_DIR is too long -> noop\n");
            }
        }
        wchar_t path[replacement_path_capacity];
        if (have_directory && build_replacement_path(directory, replacement_shaders[index].file_name,
                                                    path, replacement_path_capacity)) {
            read_replacement_shader(path, slot);
        } else if (have_directory) {
            write_log("d3d12_xs: BVH replacement shader path is too long -> noop\n");
        } else if (env_length == 0) {
            write_log("d3d12_xs: d3d12_xs.dll directory unavailable -> noop\n");
        }
    }
    ReleaseSRWLockExclusive(&replacement_shader_lock);
    return slot;
}

// ---------------------------------------------------------------------------------------------
// Desktop binding resources for the replacement PSO.
//
// The title's root signature describes the console shader's layout, so the replacement PSO gets a
// shim-owned desktop root signature instead: root SRV t0 at parameter 0 and root UAV u0 at
// parameter 1. A single 16 MiB default-heap buffer is the dummy UAV that the replacement shader
// writes into. Both objects are created once per device proxy. If either creation fails, the
// compute-PSO path keeps the source-built no-op shader and the command-list handlers stay inert.
// ---------------------------------------------------------------------------------------------
constexpr UINT64 replacement_uav_bytes = 16ull * 1024ull * 1024ull;

bool ensure_replacement_resources(ProxyDevice* proxy)
{
    if (!proxy || !proxy->real) return false;

    AcquireSRWLockExclusive(&proxy->replacement_resources_lock);
    if (!proxy->replacement_resources_attempted) {
        proxy->replacement_resources_attempted = true;

        D3D12_ROOT_PARAMETER parameters[17]{};
        parameters[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_SRV;
        parameters[0].Descriptor.ShaderRegister = 0;
        parameters[0].Descriptor.RegisterSpace = 0;
        parameters[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
        parameters[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_UAV;
        parameters[1].Descriptor.ShaderRegister = 0;
        parameters[1].Descriptor.RegisterSpace = 0;
        parameters[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
        // The L1 BVH layouts also bind 16 root constants at b0; the desktop replacements read the
        // same block (for example the header count and the console BVH base address).
        parameters[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
        parameters[2].Constants.ShaderRegister = 0;
        parameters[2].Constants.RegisterSpace = 0;
        parameters[2].Constants.Num32BitValues = 16;
        parameters[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;

        // Parameters 3..16 cover the remaining SRV/UAV registers the recompiled console shaders
        // declare (up to t7 and u7). A pipeline state only needs the registers to be present in the
        // root signature, so this wide layout lets the retarget+sign-only shaders create real
        // desktop PSOs even though their dispatch bindings are not translated yet.
        std::size_t next_parameter = 3;
        for (UINT reg = 1; reg < 8; ++reg) {
            D3D12_ROOT_PARAMETER& srv = parameters[next_parameter++];
            srv.ParameterType = D3D12_ROOT_PARAMETER_TYPE_SRV;
            srv.Descriptor.ShaderRegister = reg;
            srv.Descriptor.RegisterSpace = 0;
            srv.ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
        }
        for (UINT reg = 1; reg < 8; ++reg) {
            D3D12_ROOT_PARAMETER& uav = parameters[next_parameter++];
            uav.ParameterType = D3D12_ROOT_PARAMETER_TYPE_UAV;
            uav.Descriptor.ShaderRegister = reg;
            uav.Descriptor.RegisterSpace = 0;
            uav.ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
        }

        D3D12_ROOT_SIGNATURE_DESC root_desc{};
        root_desc.NumParameters = static_cast<UINT>(next_parameter);
        root_desc.pParameters = parameters;
        root_desc.NumStaticSamplers = 0;
        root_desc.pStaticSamplers = nullptr;
        root_desc.Flags = D3D12_ROOT_SIGNATURE_FLAG_NONE;

        ID3DBlob* signature = nullptr;
        ID3DBlob* errors = nullptr;
        HRESULT result = D3D12SerializeRootSignature(
            &root_desc, D3D_ROOT_SIGNATURE_VERSION_1, &signature, &errors);
        if (SUCCEEDED(result) && signature) {
            result = proxy->real->CreateRootSignature(
                0, signature->GetBufferPointer(), signature->GetBufferSize(),
                __uuidof(ID3D12RootSignature),
                reinterpret_cast<void**>(&proxy->replacement_root_signature));
        }
        if (errors) errors->Release();
        if (signature) signature->Release();
        if (FAILED(result) || !proxy->replacement_root_signature) {
            if (proxy->replacement_root_signature) {
                proxy->replacement_root_signature->Release();
                proxy->replacement_root_signature = nullptr;
            }
            char line[192];
            std::snprintf(line, sizeof(line),
                          "d3d12_xs: BVH replacement root signature unavailable (0x%08lx) -> "
                          "noop\n",
                          static_cast<unsigned long>(result));
            write_log(line);
        } else {
            write_log("d3d12_xs: BVH replacement root signature created "
                      "(root SRV t0 @0, root UAV u0 @1)\n");
        }

        if (proxy->replacement_root_signature) {
            D3D12_HEAP_PROPERTIES heap_properties{};
            heap_properties.Type = D3D12_HEAP_TYPE_DEFAULT;
            heap_properties.CreationNodeMask = 1;
            heap_properties.VisibleNodeMask = 1;

            D3D12_RESOURCE_DESC uav_desc{};
            uav_desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
            uav_desc.Alignment = 0;
            uav_desc.Width = replacement_uav_bytes;
            uav_desc.Height = 1;
            uav_desc.DepthOrArraySize = 1;
            uav_desc.MipLevels = 1;
            uav_desc.Format = DXGI_FORMAT_UNKNOWN;
            uav_desc.SampleDesc.Count = 1;
            uav_desc.SampleDesc.Quality = 0;
            uav_desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
            uav_desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;

            result = proxy->real->CreateCommittedResource(
                &heap_properties, D3D12_HEAP_FLAG_NONE, &uav_desc,
                D3D12_RESOURCE_STATE_UNORDERED_ACCESS, nullptr, __uuidof(ID3D12Resource),
                reinterpret_cast<void**>(&proxy->replacement_uav));
            if (FAILED(result) || !proxy->replacement_uav) {
                if (proxy->replacement_uav) {
                    proxy->replacement_uav->Release();
                    proxy->replacement_uav = nullptr;
                }
                char line[192];
                std::snprintf(line, sizeof(line),
                              "d3d12_xs: BVH replacement UAV unavailable (0x%08lx) -> noop\n",
                              static_cast<unsigned long>(result));
                write_log(line);
            } else {
                char line[192];
                std::snprintf(line, sizeof(line),
                              "d3d12_xs: BVH replacement UAV created bytes=%llu "
                              "state=UNORDERED_ACCESS addr=0x%llx\n",
                              static_cast<unsigned long long>(replacement_uav_bytes),
                              static_cast<unsigned long long>(
                                  proxy->replacement_uav->GetGPUVirtualAddress()));
                write_log(line);
            }
        }
    }
    const bool ready = proxy->replacement_root_signature && proxy->replacement_uav;
    ReleaseSRWLockExclusive(&proxy->replacement_resources_lock);
    return ready;
}

HRESULT WINAPI create_compute_pipeline_state_x(
    ProxyDevice* proxy, const D3D12_COMPUTE_PIPELINE_STATE_DESC* desc, std::uintptr_t,
    std::uintptr_t, const IID* iid, void** pipeline_state)
{
    if (!proxy || !proxy->real) return E_UNEXPECTED;
    if (!desc || !pipeline_state) return E_POINTER;
    *pipeline_state = nullptr;

    const auto& shader = noop_compute_shader_blob();
    const bool noop_ready = SUCCEEDED(shader.result) && shader.blob;

    const int replacement_index = find_replacement_shader(desc->CS);
    const bool replacement_target = replacement_index >= 0;
    const replacement_shader_cache* replacement = nullptr;
    if (replacement_target) {
        const replacement_shader_cache& cached = replacement_shader_blob(replacement_index);
        if (cached.bytes && cached.size && ensure_replacement_resources(proxy)) {
            replacement = &cached;
        }
    }
    if (!replacement && !noop_ready) return shader.result;

    D3D12_COMPUTE_PIPELINE_STATE_DESC safe = *desc;
    if (!safe.NodeMask) safe.NodeMask = 1;
    safe.CachedPSO = {};
    safe.Flags = D3D12_PIPELINE_STATE_FLAG_NONE;
    const IID& requested = iid ? *iid : __uuidof(ID3D12PipelineState);

    const char* source = "noop";
    bool uses_replacement = replacement != nullptr;
    if (replacement) {
        safe.CS = {replacement->bytes, replacement->size};
        safe.pRootSignature = proxy->replacement_root_signature;
        source = "replacement";
    } else {
        if (replacement_target) source = "noop (replacement unavailable)";
        safe.CS = {shader.blob->GetBufferPointer(), shader.blob->GetBufferSize()};
    }

    HRESULT result = proxy->real->CreateComputePipelineState(&safe, requested, pipeline_state);
    if (FAILED(result) && safe.pRootSignature && !uses_replacement) {
        safe.pRootSignature = nullptr;
        result = proxy->real->CreateComputePipelineState(&safe, requested, pipeline_state);
    }
    if (FAILED(result) && uses_replacement) {
        char line[192];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: replacement compute PSO failed 0x%08lx -> noop\n",
                      static_cast<unsigned long>(result));
        write_log(line);
        if (!noop_ready) return result;
        uses_replacement = false;
        safe.pRootSignature = desc->pRootSignature;
        safe.CS = {shader.blob->GetBufferPointer(), shader.blob->GetBufferSize()};
        source = "noop (replacement create failed)";
        *pipeline_state = nullptr;
        result = proxy->real->CreateComputePipelineState(&safe, requested, pipeline_state);
        if (FAILED(result) && safe.pRootSignature) {
            safe.pRootSignature = nullptr;
            result = proxy->real->CreateComputePipelineState(&safe, requested, pipeline_state);
        }
    }

    if (SUCCEEDED(result) && uses_replacement && *pipeline_state) {
        proxy->replacement_game_root_signature = desc->pRootSignature;
        proxy->replacement_pso = static_cast<ID3D12PipelineState*>(*pipeline_state);
        char line[224];
        std::snprintf(line, sizeof(line),
                      "d3d12_xs: replacement PSO registered pso=%p game_root=%p shim_root=%p\n",
                      *pipeline_state, static_cast<void*>(desc->pRootSignature),
                      static_cast<void*>(proxy->replacement_root_signature));
        write_log(line);
    }

    char line[192];
    const std::uint64_t incoming_hash =
        desc->CS.pShaderBytecode ? fnv1a64(desc->CS.pShaderBytecode, desc->CS.BytecodeLength) : 0ull;
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: compute PSO src=%s -> 0x%08lx (cs=%llu fnv=0x%016llx match=%d)\n", source,
                  static_cast<unsigned long>(result),
                  static_cast<unsigned long long>(desc->CS.BytecodeLength),
                  static_cast<unsigned long long>(incoming_hash), replacement_target ? 1 : 0);
    write_log(line);
    return result;
}

ProxyDevice* create_proxy(ID3D12Device* real)
{
    auto* proxy = new (std::nothrow) ProxyDevice{};
    if (!proxy) return nullptr;
    InitializeSRWLock(&proxy->replacement_resources_lock);

    proxy->vtable_memory = new (std::nothrow) void*[proxy_vtable_slots]{};
    if (!proxy->vtable_memory) {
        delete proxy;
        return nullptr;
    }

    auto* code = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, thunk_block_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!code) {
        delete[] proxy->vtable_memory;
        delete proxy;
        return nullptr;
    }

    proxy->vtable = proxy->vtable_memory;
    proxy->vtable_memory[0] = reinterpret_cast<void*>(&proxy_query_interface);
    proxy->vtable_memory[1] = reinterpret_cast<void*>(&proxy_add_ref);
    proxy->vtable_memory[2] = reinterpret_cast<void*>(&proxy_release);

    std::uint8_t* cursor = code;
    for (std::size_t slot = 3; slot < desktop_device_slots; ++slot) {
        void* thunk = cursor;
        const bool this_in_second_arg = slot == get_resource_allocation_info_slot ||
                                        slot == get_custom_heap_properties_slot;
        cursor = emit_forward_thunk(cursor, static_cast<std::uint32_t>(offsetof(ProxyDevice, real)),
                                    static_cast<std::uint32_t>(slot), this_in_second_arg);
        proxy->vtable_memory[slot] = thunk;
    }
    for (std::size_t slot = desktop_device_slots; slot < proxy_vtable_slots; ++slot) {
        void* stub = cursor;
        cursor = emit_xbox_stub(cursor, slot, reinterpret_cast<const void*>(&unimplemented_xbox_slot));
        proxy->vtable_memory[slot] = stub;
    }
    proxy->vtable_memory[create_command_queue_x_slot] =
        reinterpret_cast<void*>(&create_command_queue_x);
    proxy->vtable_memory[create_descriptor_heap_slot] =
        reinterpret_cast<void*>(&create_descriptor_heap);
    proxy->vtable_memory[create_command_signature_slot] =
        reinterpret_cast<void*>(&create_command_signature_x);
    proxy->vtable_memory[create_meta_command_slot] =
        reinterpret_cast<void*>(&create_meta_command);
    proxy->vtable_memory[create_xbox_slot73_index] =
        reinterpret_cast<void*>(&create_xbox_command_list);
    proxy->vtable_memory[slot78_slot] = reinterpret_cast<void*>(&slot78_noop);
    proxy->vtable_memory[set_frame_interval_x_slot] =
        reinterpret_cast<void*>(&set_frame_interval_x);
    proxy->vtable_memory[configure_frame_event_slot] =
        reinterpret_cast<void*>(&configure_frame_event);
    proxy->vtable_memory[create_committed_resource_x_slot] =
        reinterpret_cast<void*>(&create_committed_resource_x);
    proxy->vtable_memory[create_compute_pipeline_state_x_slot] =
        reinterpret_cast<void*>(&create_compute_pipeline_state_x);
    proxy->vtable_memory[create_shader_resource_view_x_slot] =
        reinterpret_cast<void*>(&create_shader_resource_view_x);

    if (cursor != code + thunk_block_bytes) {
        VirtualFree(code, 0, MEM_RELEASE);
        delete[] proxy->vtable_memory;
        delete proxy;
        return nullptr;
    }

    FlushInstructionCache(GetCurrentProcess(), code, thunk_block_bytes);
    DWORD previous_protection = 0;
    if (!VirtualProtect(code, thunk_block_bytes, PAGE_EXECUTE_READ, &previous_protection)) {
        VirtualFree(code, 0, MEM_RELEASE);
        delete[] proxy->vtable_memory;
        delete proxy;
        return nullptr;
    }

    proxy->thunk_memory = code;
    proxy->references = 2; // one caller reference; one process-lifetime root reference
    proxy->real = real;
    return proxy;
}
} // namespace

extern "C" HRESULT WINAPI d3d12_xs_SerializeVersionedRootSignature(
    const D3D12_VERSIONED_ROOT_SIGNATURE_DESC* root_signature,
    ID3DBlob** blob,
    ID3DBlob** error_blob)
{
    if (!root_signature) {
        return D3D12SerializeVersionedRootSignature(root_signature, blob, error_blob);
    }
    if (root_signature->Version == D3D_ROOT_SIGNATURE_VERSION_1_1) {
        const auto flags = static_cast<std::uint32_t>(root_signature->Desc_1_1.Flags);
        if (flags & observed_console_flags) {
            D3D12_VERSIONED_ROOT_SIGNATURE_DESC copy = *root_signature;
            copy.Desc_1_1.Flags = static_cast<D3D12_ROOT_SIGNATURE_FLAGS>(flags & ~observed_console_flags);
            return D3D12SerializeVersionedRootSignature(&copy, blob, error_blob);
        }
    } else if (root_signature->Version == D3D_ROOT_SIGNATURE_VERSION_1_0) {
        const auto flags = static_cast<std::uint32_t>(root_signature->Desc_1_0.Flags);
        if (flags & observed_console_flags) {
            D3D12_VERSIONED_ROOT_SIGNATURE_DESC copy = *root_signature;
            copy.Desc_1_0.Flags = static_cast<D3D12_ROOT_SIGNATURE_FLAGS>(flags & ~observed_console_flags);
            return D3D12SerializeVersionedRootSignature(&copy, blob, error_blob);
        }
    }
    return D3D12SerializeVersionedRootSignature(root_signature, blob, error_blob);
}

extern "C" HRESULT WINAPI d3d12_xs_CreateRootSignatureDeserializer(
    LPCVOID src_data,
    SIZE_T src_data_size_in_bytes,
    REFIID deserializer_interface,
    void** deserializer)
{
    return D3D12CreateRootSignatureDeserializer(
        src_data, src_data_size_in_bytes, deserializer_interface, deserializer);
}

extern "C" HRESULT WINAPI d3d12_xs_XboxCreateDevice(
    IUnknown* adapter, const void* parameters, REFIID requested_iid, void** device)
{
    if (!device) return E_POINTER;
    *device = nullptr;

    char iid_text[64];
    format_iid(requested_iid, iid_text, sizeof(iid_text));
    char line[256];
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: XboxCreateDevice iid=%s adapter=%p parameters=%p\n", iid_text,
                  static_cast<void*>(adapter), const_cast<void*>(parameters));
    write_log(line);

    const bool supported_request = IsEqualIID(requested_iid, xbox_device_iid) ||
                                   IsEqualIID(requested_iid, __uuidof(ID3D12Device)) ||
                                   IsEqualIID(requested_iid, __uuidof(IUnknown));
    if (!supported_request) {
        write_log("d3d12_xs: XboxCreateDevice unsupported iid -> E_NOINTERFACE\n");
        return E_NOINTERFACE;
    }

    // The console parameter block is not interpreted. The observed call passes adapter=null; a
    // non-null adapter could be an Xbox wrapper with an unknown ABI, so desktop D3D12 picks the
    // default adapter instead of forwarding it.
    // The console compute shaders are Shader Model 6.5, which needs a D3D12_2-capable device; a
    // FL12_0 device rejects their pipeline states with E_INVALIDARG. Prefer the highest feature
    // level the adapter reports and fall back gracefully.
    ID3D12Device* real_device = nullptr;
    HRESULT create_hr = E_FAIL;
    D3D_FEATURE_LEVEL created_level = D3D_FEATURE_LEVEL_12_0;
    const D3D_FEATURE_LEVEL levels_to_try[] = {D3D_FEATURE_LEVEL_12_2, D3D_FEATURE_LEVEL_12_1,
                                                D3D_FEATURE_LEVEL_12_0};
    for (D3D_FEATURE_LEVEL level : levels_to_try) {
        create_hr = D3D12CreateDevice(nullptr, level, __uuidof(ID3D12Device),
                                      reinterpret_cast<void**>(&real_device));
        if (SUCCEEDED(create_hr) && real_device) {
            created_level = level;
            break;
        }
        real_device = nullptr;
    }
    if (FAILED(create_hr) || !real_device) {
        std::snprintf(line, sizeof(line), "d3d12_xs: D3D12CreateDevice failed hr=0x%08lx\n",
                      static_cast<unsigned long>(create_hr));
        write_log(line);
        return FAILED(create_hr) ? create_hr : E_FAIL;
    }

    D3D12_FEATURE_DATA_D3D12_OPTIONS5 options5{};
    const HRESULT feature_hr = real_device->CheckFeatureSupport(
        D3D12_FEATURE_D3D12_OPTIONS5, &options5, sizeof(options5));
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: device level=0x%x raytracing tier=%u feature_hr=0x%08lx\n",
                  static_cast<unsigned>(created_level), static_cast<unsigned>(options5.RaytracingTier),
                  static_cast<unsigned long>(feature_hr));
    write_log(line);
    sync_cached_descriptor_increment(real_device);


    ProxyDevice* proxy = create_proxy(real_device);
    if (!proxy) {
        real_device->Release();
        write_log("d3d12_xs: device proxy allocation failed -> E_OUTOFMEMORY\n");
        return E_OUTOFMEMORY;
    }

    std::snprintf(line, sizeof(line),
                  "d3d12_xs: device proxy slots=%llu (iunknown=3, desktop=%llu, xbox=%llu) real=%p "
                  "proxy=%p\n",
                  static_cast<unsigned long long>(proxy_vtable_slots),
                  static_cast<unsigned long long>(desktop_device_slots),
                  static_cast<unsigned long long>(xbox_appended_slots),
                  static_cast<void*>(real_device), static_cast<void*>(proxy));
    write_log(line);

    *device = proxy;
    return S_OK;
}

// Loader-gap export measured on the inspected executable (docs/experiments.md). Desktop D3D12
// owns device virtual memory, so there is no equivalent configuration step: report success and
// leave the desktop allocator in charge. The parameter shape is a placeholder, not a verified
// Scarlett ABI.
extern "C" HRESULT WINAPI d3d12_xs_ConfigureVirtualMemoryX(ID3D12Device*, const void*)
{
    return S_OK;
}
