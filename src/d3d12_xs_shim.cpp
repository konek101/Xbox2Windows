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
//   * Slot 73 (offset 0x248), measured in the title, is the exception: it returns a bring-up fake
//     object instead of E_NOTIMPL. See the slot-73 section below.
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
constexpr LONG max_log_messages = 256;
constexpr LONGLONG max_log_file_bytes = 64 * 1024;
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
// Slot-73 bring-up fake object.
//
// The observed title calls Xbox device vtable slot 73 (offset 0x248) and treats a negative HRESULT
// as fatal. The real Xbox method and the object it returns are not documented here, so this returns
// a process-wide singleton that is deliberately a no-op. It is NOT console-accurate.
//
//   * Slots 0..2 implement QueryInterface/AddRef/Release.
//   * Every other slot (3..255) is a generated x64 stub that loads the slot number into RDX and
//     tail-calls one common handler, which logs the slot and returns S_OK. That covers the
//     [object_vtable + 0x420] (slot 132) call the observed caller makes on the result, so no slot
//     can ever return E_NOTIMPL.
//
// The stub clobbers RDX with the slot number. That is safe because the handler ignores method
// arguments. For a hidden-return-buffer (sret) method RCX is the caller's return buffer rather than
// `this`; the handler logs it as an opaque pointer and never dereferences it, and such methods
// return S_OK without filling the buffer. That remains an uncertainty.
// ---------------------------------------------------------------------------------------------
constexpr std::size_t create_xbox_slot73_index = 73;
constexpr std::size_t fake_slot73_vtable_slots = 256;
constexpr std::size_t fake_slot73_stub_count = fake_slot73_vtable_slots - 3;
constexpr std::size_t fake_slot73_stub_block_bytes = xbox_stub_bytes * fake_slot73_stub_count;
constexpr std::size_t fake_slot73_observed_result_method = 0x420 / sizeof(void*);
static_assert(create_xbox_slot73_index >= desktop_device_slots &&
                  create_xbox_slot73_index < proxy_vtable_slots,
              "slot 73 must be an Xbox-appended slot of the device proxy");
static_assert(fake_slot73_vtable_slots > fake_slot73_observed_result_method,
              "the fake object vtable must cover [vtable+0x420]");

struct FakeSlot73Object {
    void** vtable;            // +0  COM vtable pointer seen by the caller.
    volatile LONG references; // +8  singleton IUnknown reference count.
};

void* fake_slot73_vtable[fake_slot73_vtable_slots] = {};
FakeSlot73Object fake_slot73_object{};
bool fake_slot73_ready = false;
INIT_ONCE fake_slot73_init_once = INIT_ONCE_STATIC_INIT;

ULONG WINAPI fake_slot73_add_ref(FakeSlot73Object* self)
{
    return static_cast<ULONG>(InterlockedIncrement(&self->references));
}

// Static singleton lifetime: never destroy. Clamp instead of letting the count wrap.
ULONG WINAPI fake_slot73_release(FakeSlot73Object* self)
{
    const LONG remaining = InterlockedDecrement(&self->references);
    if (remaining < 0) {
        InterlockedExchange(&self->references, 0);
        return 0;
    }
    return static_cast<ULONG>(remaining);
}

// Choice: answer every IID with the same singleton. The interface the title expects from slot 73 is
// unknown, and every non-IUnknown method is a safe no-op, so E_NOINTERFACE would only add a failure
// path. The trade-off is possible type confusion if a caller uses an interface-specific method.
HRESULT WINAPI fake_slot73_query_interface(FakeSlot73Object* self, REFIID iid, void** out)
{
    (void)iid;
    if (!out) return E_POINTER;
    *out = nullptr;
    fake_slot73_add_ref(self);
    *out = self;
    return S_OK;
}

HRESULT WINAPI fake_slot73_default(FakeSlot73Object* self, std::uintptr_t slot)
{
    char line[160];
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: slot-73 fake object method %llu called (self=%p) -> S_OK\n",
                  static_cast<unsigned long long>(slot), static_cast<void*>(self));
    write_log(line);
    return S_OK;
}

BOOL CALLBACK init_fake_slot73_object(PINIT_ONCE, PVOID, PVOID*)
{
    auto* code = static_cast<std::uint8_t*>(VirtualAlloc(
        nullptr, fake_slot73_stub_block_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!code) return FALSE;

    fake_slot73_vtable[0] = reinterpret_cast<void*>(&fake_slot73_query_interface);
    fake_slot73_vtable[1] = reinterpret_cast<void*>(&fake_slot73_add_ref);
    fake_slot73_vtable[2] = reinterpret_cast<void*>(&fake_slot73_release);

    std::uint8_t* cursor = code;
    for (std::size_t slot = 3; slot < fake_slot73_vtable_slots; ++slot) {
        void* stub = cursor;
        cursor = emit_xbox_stub(cursor, slot, reinterpret_cast<const void*>(&fake_slot73_default));
        fake_slot73_vtable[slot] = stub;
    }

    if (cursor != code + fake_slot73_stub_block_bytes) {
        VirtualFree(code, 0, MEM_RELEASE);
        return FALSE;
    }

    FlushInstructionCache(GetCurrentProcess(), code, fake_slot73_stub_block_bytes);
    DWORD previous_protection = 0;
    if (!VirtualProtect(code, fake_slot73_stub_block_bytes, PAGE_EXECUTE_READ,
                        &previous_protection)) {
        VirtualFree(code, 0, MEM_RELEASE);
        return FALSE;
    }

    fake_slot73_object.vtable = fake_slot73_vtable;
    fake_slot73_object.references = 0;
    fake_slot73_ready = true;
    return TRUE;
}

// Xbox device vtable slot 73 (offset 0x248). Under the x64 calling convention arguments 5 and 6
// arrive on the stack; only the out pointer is interpreted. The descriptor and the other arguments
// are deliberately not dereferenced.
HRESULT WINAPI create_xbox_slot73(ProxyDevice* proxy, const void* desc, void* r8, uintptr_t r9,
                                  void* arg5, void** out)
{
    (void)r8;
    (void)r9;
    (void)arg5;
    if (!out) return E_POINTER;
    *out = nullptr;

    if (!InitOnceExecuteOnce(&fake_slot73_init_once, init_fake_slot73_object, nullptr, nullptr) ||
        !fake_slot73_ready) {
        write_log("d3d12_xs: slot-73 fake object initialization failed -> E_OUTOFMEMORY\n");
        return E_OUTOFMEMORY;
    }

    FakeSlot73Object* object = &fake_slot73_object;
    fake_slot73_add_ref(object);
    *out = object;

    char line[192];
    std::snprintf(line, sizeof(line),
                  "d3d12_xs: xbox vtable slot 73 called (device=%p desc=%p arg5=%p) -> fake "
                  "object %p\n",
                  static_cast<void*>(proxy), const_cast<void*>(desc), arg5,
                  static_cast<void*>(object));
    write_log(line);
    return S_OK;
}

// Observed title call at 0x2478de4: Xbox device slot 0x278 (79) with scalar arguments and no out
// pointer, HRESULT checked only for >= 0. This is a desktop-safe no-op until the Xbox method is
// measured; it is likely a frame/interval configuration call.
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

// The measured title calls GDK CreateCommandQueueX at offset 0x180 (slot 48), before the desktop
// Device1+ methods. Translate its Xbox queue descriptor to the desktop descriptor and use slot 8 of
// the real device. Only the Type field is measured; priority/flags/node are desktop defaults.
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
    proxy->vtable_memory[create_xbox_slot73_index] =
        reinterpret_cast<void*>(&create_xbox_slot73);
    proxy->vtable_memory[set_frame_interval_x_slot] =
        reinterpret_cast<void*>(&set_frame_interval_x);

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
    proxy->references = 1;
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
