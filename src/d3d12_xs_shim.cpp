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
HRESULT WINAPI unimplemented_xbox_slot(ProxyDevice* self, std::uintptr_t slot)
{
    char line[192];
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: xbox vtable slot %llu called (this=%p) -> E_NOTIMPL\n",
                  static_cast<unsigned long long>(slot), static_cast<void*>(self));
    write_log(line);
    return E_NOTIMPL;
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
//   * Slots 3..27 are the fixed base ID3D12GraphicsCommandList methods (3 IUnknown + 4
//     ID3D12Object + 1 ID3D12DeviceChild + 1 ID3D12CommandList + 18 ID3D12GraphicsCommandList),
//     including slot 9 Close. Each slot is a generated x64 thunk that swaps the proxy `this` for
//     the real desktop list and tail-jumps to the same desktop vtable slot.
//   * Slots 28..255 are console reordering / unknown methods. Their stubs log the slot and return
//     E_NOTIMPL, except the measured tail calls slot 131 (0x418) and slot 132 (0x420), which have
//     no out parameter and whose return values are ignored: those log and return S_OK.
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
constexpr std::size_t command_list_forward_last = 27;
constexpr std::size_t command_list_stub_first = command_list_forward_last + 1;
constexpr std::size_t command_list_forward_count =
    command_list_forward_last - command_list_forward_first + 1;
constexpr std::size_t command_list_stub_count =
    command_list_vtable_slots - command_list_stub_first;
constexpr std::size_t command_list_thunk_block_bytes =
    forward_thunk_bytes * command_list_forward_count + xbox_stub_bytes * command_list_stub_count;
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

D3D12_CPU_DESCRIPTOR_HANDLE WINAPI descriptor_heap_get_cpu(DescriptorHeapProxy* proxy)
{
    return proxy->real->GetCPUDescriptorHandleForHeapStart();
}

D3D12_GPU_DESCRIPTOR_HANDLE WINAPI descriptor_heap_get_gpu(DescriptorHeapProxy* proxy)
{
    return proxy->real->GetGPUDescriptorHandleForHeapStart();
}

HRESULT WINAPI descriptor_heap_unimplemented(DescriptorHeapProxy*)
{
    return E_NOTIMPL;
}

DescriptorHeapProxy* create_descriptor_heap_proxy(ID3D12DescriptorHeap* real)
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
    proxy->vtable_memory[9] = reinterpret_cast<void*>(&descriptor_heap_get_cpu);
    proxy->vtable_memory[10] = reinterpret_cast<void*>(&descriptor_heap_get_gpu);
    return proxy;
}

constexpr std::size_t create_descriptor_heap_slot = 14;
constexpr UINT desktop_shader_visible_limit = 1'000'000;

HRESULT WINAPI create_descriptor_heap(ProxyDevice* proxy, const D3D12_DESCRIPTOR_HEAP_DESC* desc,
                                      REFIID iid, void** heap)
{
    if (!proxy || !proxy->real) return E_UNEXPECTED;
    if (!desc || !heap) return E_POINTER;
    *heap = nullptr;
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
    DescriptorHeapProxy* wrapper = create_descriptor_heap_proxy(real_heap);
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

HRESULT WINAPI create_shader_resource_view_x(ProxyDevice*, const D3D12_CPU_DESCRIPTOR_HANDLE*,
                                             const void*, std::uint32_t)
{
    return S_OK;
}

// Xbox slot 62 is measured as compute-PSO creation (root-signature pointer, DXBC blob, IID on the
// stack, out on the stack), not desktop ID3D12Device5::CreateStateObject. The title's blob is Xbox
// DXIL, so create a source-built no-op SM5 compute PSO to keep the object graph valid. The BVH
// dispatches become no-ops until the package DXIL is retargeted.
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

HRESULT WINAPI create_compute_pipeline_state_x(
    ProxyDevice* proxy, const D3D12_COMPUTE_PIPELINE_STATE_DESC* desc, std::uintptr_t,
    std::uintptr_t, const IID* iid, void** pipeline_state)
{
    if (!proxy || !proxy->real) return E_UNEXPECTED;
    if (!desc || !pipeline_state) return E_POINTER;
    *pipeline_state = nullptr;
    const auto& shader = noop_compute_shader_blob();
    if (FAILED(shader.result) || !shader.blob) return shader.result;
    D3D12_COMPUTE_PIPELINE_STATE_DESC safe = *desc;
    if (!safe.NodeMask) safe.NodeMask = 1;
    safe.CS = {shader.blob->GetBufferPointer(), shader.blob->GetBufferSize()};
    safe.CachedPSO = {};
    safe.Flags = D3D12_PIPELINE_STATE_FLAG_NONE;
    const IID& requested = iid ? *iid : __uuidof(ID3D12PipelineState);
    HRESULT result = proxy->real->CreateComputePipelineState(&safe, requested, pipeline_state);
    if (FAILED(result) && safe.pRootSignature) {
        safe.pRootSignature = nullptr;
        result = proxy->real->CreateComputePipelineState(&safe, requested, pipeline_state);
    }
    char line[192];
    std::snprintf(line, sizeof(line), "d3d12_xs: noop compute PSO -> 0x%08lx\n",
                  static_cast<unsigned long>(result));
    write_log(line);
    return result;
}

ProxyDevice* create_proxy(ID3D12Device* real)
{
    auto* proxy = new (std::nothrow) ProxyDevice{};
    if (!proxy) return nullptr;

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
    ID3D12Device* real_device = nullptr;
    const HRESULT create_hr = D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_12_0,
                                                __uuidof(ID3D12Device),
                                                reinterpret_cast<void**>(&real_device));
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
                  "d3d12_xs: device raytracing tier=%u feature_hr=0x%08lx\n",
                  static_cast<unsigned>(options5.RaytracingTier),
                  static_cast<unsigned long>(feature_hr));
    write_log(line);

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
