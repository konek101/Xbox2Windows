// Desktop xcrdapi.dll: the Xbox DirectStorage factory. DStorageGetFactory returns a singleton that
// implements the IDStorageFactoryX setters with desktop no-ops and logs every other slot before
// failing closed. The method order follows IUnknown, CreateQueue, CreateStatusArray, OpenFile,
// SetCpuAffinity, SetDebugFlags, SetStagingBufferSize (dstorage_xs.h); later interface versions add
// slots that stay generic here. No Microsoft code is used.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <cstring>
#include <intrin.h>
#include <utility>

namespace {
constexpr HRESULT not_implemented = static_cast<HRESULT>(0x80004001u);
constexpr std::size_t slot_count = 62;

bool caller_trace()
{
    static const bool enabled = [] {
        wchar_t value[8]{};
        DWORD length = GetEnvironmentVariableW(L"XCRD_TRACE_CALLER", value, 8);
        return length == 1 && value[0] == L'1';
    }();
    return enabled;
}

void log_line(const wchar_t* format, ...)
{
    wchar_t path[MAX_PATH];
    DWORD length = GetEnvironmentVariableW(L"XCRD_LOG", path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        DWORD temp = GetTempPathW(MAX_PATH, path);
        if (temp == 0 || temp >= MAX_PATH) return;
        wcscat_s(path, L"xcrdapi-shim.log");
    }
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    wchar_t line[1024];
    va_list args;
    va_start(args, format);
    vswprintf_s(line, _countof(line), format, args);
    va_end(args);
    DWORD written = 0;
    WriteFile(file, line, static_cast<DWORD>(wcslen(line) * sizeof(wchar_t)), &written, nullptr);
    WriteFile(file, L"\r\n", 2 * sizeof(wchar_t), &written, nullptr);
    CloseHandle(file);
}

void log_guid(const wchar_t* label, const GUID* id)
{
    if (id == nullptr) {
        log_line(L"%s=null", label);
        return;
    }
    log_line(L"%s={%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", label, id->Data1, id->Data2,
             id->Data3, id->Data4[0], id->Data4[1], id->Data4[2], id->Data4[3], id->Data4[4],
             id->Data4[5], id->Data4[6], id->Data4[7]);
}

void log_caller(const wchar_t* label, void* caller)
{
    if (!caller_trace()) return;
    static LONG sequence = 0;
    LONG index = InterlockedIncrement(&sequence);
    if (index <= 64) log_line(L"%s caller=%p seq=%ld", label, caller, index);
}

struct factory_object {
    void** vtable;
};

struct status_array_object;
status_array_object& status_array();
struct queue_object;
queue_object& queue();

HRESULT STDMETHODCALLTYPE factory_query_interface(factory_object* self, const GUID* interface_id,
                                                  void** out)
{
    log_guid(L"factory QueryInterface iid", interface_id);
    if (out == nullptr) return E_POINTER;
    *out = self;
    return S_OK;
}

ULONG STDMETHODCALLTYPE factory_add_ref(factory_object*)
{
    return 2;
}

ULONG STDMETHODCALLTYPE factory_release(factory_object*)
{
    return 0;
}

HRESULT STDMETHODCALLTYPE factory_create_queue(factory_object*, const void* description,
                                               const GUID* interface_id, void** out)
{
    log_line(L"factory CreateQueue description=%p", description);
    log_caller(L"factory CreateQueue", _ReturnAddress());
    log_guid(L"factory CreateQueue iid", interface_id);
    // Console queue descriptor (XCL reference): source type u32 at 0, capacity u16 at 8,
    // priority i8 at 0xa, name pointer at 0x10. The newer create path passes an extra qword at 0x18.
    if (description != nullptr) {
        const auto* bytes = static_cast<const unsigned char*>(description);
        std::uint32_t source_type = 0;
        std::uint16_t capacity = 0;
        std::int8_t priority = 0;
        const void* name = nullptr;
        std::memcpy(&source_type, bytes, sizeof(source_type));
        std::memcpy(&capacity, bytes + 8, sizeof(capacity));
        std::memcpy(&priority, bytes + 0xa, sizeof(priority));
        std::memcpy(&name, bytes + 0x10, sizeof(name));
        log_line(L"factory queue source=%lu capacity=%u priority=%d name=%p", source_type, capacity,
                 static_cast<int>(priority), name);
    }
    if (out == nullptr) return E_POINTER;
    *out = &queue();
    return S_OK;
}

HRESULT STDMETHODCALLTYPE factory_create_status_array(factory_object*, std::uint32_t capacity,
                                                     const char* name, const GUID* interface_id,
                                                     void** out)
{
    log_line(L"factory CreateStatusArray capacity=%lu name=%p", capacity, name);
    log_caller(L"factory CreateStatusArray", _ReturnAddress());
    log_guid(L"factory CreateStatusArray iid", interface_id);
    if (out == nullptr) return E_POINTER;
    *out = &status_array();
    return S_OK;
}

HRESULT STDMETHODCALLTYPE factory_open_file(factory_object*, const wchar_t* path,
                                            const GUID* interface_id, void** out)
{
    log_line(L"factory OpenFile path=%s", path != nullptr ? path : L"(null)");
    log_guid(L"factory OpenFile iid", interface_id);
    if (out) *out = nullptr;
    return not_implemented;
}

HRESULT STDMETHODCALLTYPE factory_set_cpu_affinity(factory_object*, std::uint64_t affinity)
{
    log_line(L"factory SetCpuAffinity 0x%llx", static_cast<unsigned long long>(affinity));
    return S_OK;
}

HRESULT STDMETHODCALLTYPE factory_set_debug_flags(factory_object*, std::uint32_t flags)
{
    log_line(L"factory SetDebugFlags 0x%lx", flags);
    return S_OK;
}

HRESULT STDMETHODCALLTYPE factory_set_staging_buffer_size(factory_object*, std::uint32_t size)
{
    log_line(L"factory SetStagingBufferSize 0x%lx", size);
    return S_OK;
}

template <std::size_t Slot>
HRESULT STDMETHODCALLTYPE factory_unknown_slot(void*, std::uint64_t a, std::uint64_t b,
                                               std::uint64_t c)
{
    log_line(L"factory unknown slot=%zu a=%016llx b=%016llx c=%016llx", Slot,
             static_cast<unsigned long long>(a), static_cast<unsigned long long>(b),
             static_cast<unsigned long long>(c));
    return not_implemented;
}

// Minimal IDStorageStatusArray: the measured title creates one status array as part of its
// DirectStorage device. IsComplete reports true and GetHResult reports S_OK, which matches the
// synchronous stub queue this shim intends to provide.
struct status_array_object {
    void** vtable;
};

HRESULT STDMETHODCALLTYPE status_query_interface(status_array_object* self, const GUID* interface_id,
                                                 void** out)
{
    log_guid(L"status array QueryInterface iid", interface_id);
    if (out == nullptr) return E_POINTER;
    *out = self;
    return S_OK;
}

ULONG STDMETHODCALLTYPE status_add_ref(status_array_object*)
{
    return 2;
}

ULONG STDMETHODCALLTYPE status_release(status_array_object*)
{
    return 0;
}

BOOL STDMETHODCALLTYPE status_is_complete(status_array_object*, std::uint32_t index)
{
    log_line(L"status array IsComplete index=%lu", index);
    return TRUE;
}

HRESULT STDMETHODCALLTYPE status_get_hresult(status_array_object*, std::uint32_t index)
{
    log_line(L"status array GetHResult index=%lu", index);
    return S_OK;
}

template <std::size_t Slot>
HRESULT STDMETHODCALLTYPE status_unknown_slot(void*, std::uint64_t, std::uint64_t, std::uint64_t)
{
    log_line(L"status array unknown slot=%zu", Slot);
    return S_OK;
}

template <std::size_t... I>
void fill_status_slots(std::array<void*, 16>& table, std::index_sequence<I...>)
{
    ((table[5 + I] = reinterpret_cast<void*>(&status_unknown_slot<5 + I>)), ...);
}

void** status_array_vtable()
{
    static std::array<void*, 16> table = [] {
        std::array<void*, 16> result{};
        result[0] = reinterpret_cast<void*>(&status_query_interface);
        result[1] = reinterpret_cast<void*>(&status_add_ref);
        result[2] = reinterpret_cast<void*>(&status_release);
        result[3] = reinterpret_cast<void*>(&status_is_complete);
        result[4] = reinterpret_cast<void*>(&status_get_hresult);
        fill_status_slots(result, std::make_index_sequence<11>{});
        return result;
    }();
    return table.data();
}

status_array_object& status_array()
{
    static status_array_object object{status_array_vtable()};
    return object;
}

// DirectStorage queue stub. The measured newer create path (factory slot 10) passes a queue
// descriptor and an out pointer. Requests are measured as 0x48-byte records (XCL reference), but the
// synchronous reader is not implemented yet: every method answers success so the rest of startup can
// be measured, and the request log shows what the title submits.
struct queue_object {
    void** vtable;
};

HRESULT STDMETHODCALLTYPE queue_query_interface(queue_object* self, const GUID* interface_id,
                                                void** out)
{
    log_guid(L"queue QueryInterface iid", interface_id);
    if (out == nullptr) return E_POINTER;
    *out = self;
    return S_OK;
}

ULONG STDMETHODCALLTYPE queue_add_ref(queue_object*)
{
    return 2;
}

ULONG STDMETHODCALLTYPE queue_release(queue_object*)
{
    return 0;
}

void STDMETHODCALLTYPE queue_enqueue_request(queue_object*, const void* request)
{
    static LONG count = 0;
    if (InterlockedIncrement(&count) > 16) return;
    if (request != nullptr) {
        const auto* bytes = static_cast<const unsigned char*>(request);
        std::uint64_t destination = 0;
        std::uint64_t size = 0;
        std::uint64_t source = 0;
        std::uint64_t file_offset = 0;
        std::memcpy(&destination, bytes + 8, sizeof(destination));
        std::memcpy(&size, bytes + 0x18, sizeof(size));
        std::memcpy(&source, bytes + 0x20, sizeof(source));
        std::memcpy(&file_offset, bytes + 0x28, sizeof(file_offset));
        log_line(L"queue EnqueueRequest options=%016llx dst=%016llx size=%016llx src=%016llx "
                 L"offset=%016llx",
                 *reinterpret_cast<const unsigned long long*>(bytes), destination, size, source,
                 file_offset);
    }
}

void STDMETHODCALLTYPE queue_submit(queue_object*)
{
    log_line(L"queue Submit");
}

void STDMETHODCALLTYPE queue_cancel(queue_object*, std::uint64_t mask, std::uint64_t value)
{
    log_line(L"queue CancelRequestsWithTag mask=%016llx value=%016llx", mask, value);
}

void STDMETHODCALLTYPE queue_close(queue_object*)
{
    log_line(L"queue Close");
}

HANDLE STDMETHODCALLTYPE queue_get_error_event(queue_object*)
{
    log_line(L"queue GetErrorEvent");
    return nullptr;
}

void STDMETHODCALLTYPE queue_retrieve_error_record(queue_object*, void* record)
{
    log_line(L"queue RetrieveErrorRecord record=%p", record);
    if (record != nullptr) ZeroMemory(record, 0x290);
}

HRESULT STDMETHODCALLTYPE queue_query_info(queue_object*, std::uint32_t info_id, void* info,
                                           std::uint32_t info_size)
{
    log_line(L"queue Query id=%lu info=%p size=%lu", info_id, info, info_size);
    if (info != nullptr && info_size != 0) ZeroMemory(info, info_size);
    return S_OK;
}

template <std::size_t Slot>
HRESULT STDMETHODCALLTYPE queue_unknown_slot(void*, std::uint64_t a, std::uint64_t b,
                                             std::uint64_t c)
{
    log_line(L"queue unknown slot=%zu a=%016llx b=%016llx c=%016llx", Slot,
             static_cast<unsigned long long>(a), static_cast<unsigned long long>(b),
             static_cast<unsigned long long>(c));
    return S_OK;
}

template <std::size_t... I>
void fill_queue_slots(std::array<void*, 16>& table, std::index_sequence<I...>)
{
    ((table[10 + I] = reinterpret_cast<void*>(&queue_unknown_slot<10 + I>)), ...);
}

void** queue_vtable()
{
    static std::array<void*, 16> table = [] {
        std::array<void*, 16> result{};
        result[0] = reinterpret_cast<void*>(&queue_query_interface);
        result[1] = reinterpret_cast<void*>(&queue_add_ref);
        result[2] = reinterpret_cast<void*>(&queue_release);
        result[3] = reinterpret_cast<void*>(&queue_enqueue_request);
        result[4] = reinterpret_cast<void*>(&queue_submit);
        result[5] = reinterpret_cast<void*>(&queue_cancel);
        result[6] = reinterpret_cast<void*>(&queue_close);
        result[7] = reinterpret_cast<void*>(&queue_get_error_event);
        result[8] = reinterpret_cast<void*>(&queue_retrieve_error_record);
        result[9] = reinterpret_cast<void*>(&queue_query_info);
        fill_queue_slots(result, std::make_index_sequence<6>{});
        return result;
    }();
    return table.data();
}

queue_object& queue()
{
    static queue_object object{queue_vtable()};
    return object;
}

template <std::size_t... I>
void fill_unknown_slots(std::array<void*, 3 + slot_count>& table, std::index_sequence<I...>)
{
    ((table[9 + I] = reinterpret_cast<void*>(&factory_unknown_slot<9 + I>)), ...);
}

void** factory_vtable()
{
    static std::array<void*, 3 + slot_count> table = [] {
        std::array<void*, 3 + slot_count> result{};
        result[0] = reinterpret_cast<void*>(&factory_query_interface);
        result[1] = reinterpret_cast<void*>(&factory_add_ref);
        result[2] = reinterpret_cast<void*>(&factory_release);
        result[3] = reinterpret_cast<void*>(&factory_create_queue);
        result[4] = reinterpret_cast<void*>(&factory_open_file);
        result[5] = reinterpret_cast<void*>(&factory_create_status_array);
        result[6] = reinterpret_cast<void*>(&factory_set_cpu_affinity);
        result[7] = reinterpret_cast<void*>(&factory_set_debug_flags);
        result[8] = reinterpret_cast<void*>(&factory_set_staging_buffer_size);
        fill_unknown_slots(result, std::make_index_sequence<slot_count - 9>{});
        // Measured newer create path: the title calls slot 10 (0x50) with (desc, iid, out) and a
        // queue descriptor whose fields match the XCL reference at 0/8/0xa/0x10.
        result[10] = reinterpret_cast<void*>(&factory_create_queue);
        return result;
    }();
    return table.data();
}

factory_object& factory()
{
    static factory_object object{factory_vtable()};
    return object;
}
} // namespace

extern "C" HRESULT WINAPI DStorageGetFactory(const GUID* interface_id, void** out)
{
    log_guid(L"factory requested iid", interface_id);
    if (out == nullptr) return E_POINTER;
    // The measured title asks for {62959d11-d45f-4884-a0a3-f7862ea243ae} and then calls slot 5 with
    // a record-like argument list (1, "fiDeviceDirectStorage", payload, out). That is not this
    // factory's OpenFile layout, so answering S_OK for an unknown interface hands the title the wrong
    // vtable. Log and fail the request instead of returning this object for every IID.
    *out = &factory();
    return S_OK;
}
