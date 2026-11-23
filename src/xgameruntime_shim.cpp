// Desktop xgameruntime.dll for GDK titles that load the console runtime by name at run time.
// The exported entry points and the QueryApiImpl COM dispatch match the public clean-room
// documentation in xodus-gaming/xgameruntime-docs. QueryApiImpl hands out one generic object so a
// bring-up run records the requested class/interface and method slots; the slots return E_NOTIMPL
// until a measured desktop policy is added for them. No Microsoft code is used.
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
#include <utility>

namespace {
constexpr HRESULT not_implemented = static_cast<HRESULT>(0x80004001u);
constexpr std::size_t slot_count = 256;

void log_line(const wchar_t* format, ...)
{
    wchar_t path[MAX_PATH];
    DWORD length = GetEnvironmentVariableW(L"XGR_LOG", path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        DWORD temp = GetTempPathW(MAX_PATH, path);
        if (temp == 0 || temp >= MAX_PATH) return;
        wcscat_s(path, L"xgameruntime-shim.log");
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

struct shim_object {
    void** vtable;
};

HRESULT STDMETHODCALLTYPE shim_query_interface(shim_object* self, const GUID* interface_id,
                                               void** out)
{
    log_guid(L"object QueryInterface iid", interface_id);
    if (out == nullptr) return E_POINTER;
    *out = self;
    return S_OK;
}

ULONG STDMETHODCALLTYPE shim_add_ref(shim_object*)
{
    return 2;
}

ULONG STDMETHODCALLTYPE shim_release(shim_object*)
{
    return 0;
}

template <std::size_t Slot>
HRESULT STDMETHODCALLTYPE shim_slot(void* self, std::uint64_t a, std::uint64_t b, std::uint64_t c)
{
    log_line(L"method slot=%zu self=%p a=%016llx b=%016llx c=%016llx", Slot, self,
             static_cast<unsigned long long>(a), static_cast<unsigned long long>(b),
             static_cast<unsigned long long>(c));
    return not_implemented;
}

template <std::size_t... I>
std::array<void*, 3 + sizeof...(I)> make_vtable(std::index_sequence<I...>)
{
    return {reinterpret_cast<void*>(&shim_query_interface), reinterpret_cast<void*>(&shim_add_ref),
            reinterpret_cast<void*>(&shim_release), reinterpret_cast<void*>(&shim_slot<I>)...};
}

void** generic_vtable()
{
    static std::array<void*, 3 + slot_count> table =
        make_vtable(std::make_index_sequence<slot_count>{});
    return table.data();
}

shim_object& generic_object()
{
    static shim_object object{generic_vtable()};
    return object;
}
} // namespace

extern "C" HRESULT WINAPI DllCanUnloadNow()
{
    return S_FALSE;
}

extern "C" HRESULT WINAPI InitializeApiImpl(std::uint64_t gdk_version, std::uint64_t gs_version)
{
    log_line(L"InitializeApiImpl gdk=0x%llx gs=0x%llx",
             static_cast<unsigned long long>(gdk_version),
             static_cast<unsigned long long>(gs_version));
    return S_OK;
}

extern "C" HRESULT WINAPI InitializeApiImplEx(std::uint64_t gdk_version, std::uint64_t gs_version,
                                              std::uint8_t mode)
{
    log_line(L"InitializeApiImplEx gdk=0x%llx gs=0x%llx mode=0x%02x",
             static_cast<unsigned long long>(gdk_version),
             static_cast<unsigned long long>(gs_version), mode);
    return S_OK;
}

extern "C" HRESULT WINAPI InitializeApiImplEx2(std::uint64_t gdk_version, std::uint64_t gs_version,
                                               std::uint8_t mode, const void* options)
{
    log_line(L"InitializeApiImplEx2 gdk=0x%llx gs=0x%llx mode=0x%02x options=%p",
             static_cast<unsigned long long>(gdk_version),
             static_cast<unsigned long long>(gs_version), mode, options);
    if (options != nullptr) {
        const auto* words = static_cast<const std::uint32_t*>(options);
        log_line(L"InitializeApiImplEx2 options words=%08lx %08lx %p", words[0], words[1],
                 *reinterpret_cast<const void* const*>(words + 2));
    }
    return S_OK;
}

extern "C" HRESULT WINAPI QueryApiImpl(const GUID* class_id, const GUID* interface_id, void** out)
{
    log_guid(L"QueryApiImpl class", class_id);
    log_guid(L"QueryApiImpl iid", interface_id);
    if (out == nullptr) return E_POINTER;
    *out = &generic_object();
    return S_OK;
}

extern "C" HRESULT WINAPI UninitializeApiImpl()
{
    log_line(L"UninitializeApiImpl");
    return S_OK;
}

extern "C" HRESULT WINAPI XErrorReport(HRESULT status, const char* message)
{
    wchar_t wide[512] = {};
    if (message != nullptr) MultiByteToWideChar(CP_UTF8, 0, message, -1, wide, 512);
    log_line(L"XErrorReport status=0x%08lx message=%s", static_cast<unsigned long>(status), wide);
    return S_OK;
}
