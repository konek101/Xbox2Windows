// Desktop xgameruntime.dll for GDK titles that load the console runtime by name at run time.
// The exported entry points and the QueryApiImpl COM dispatch follow the public clean-room ABI
// notes for xgameruntime and the public GDK function layouts. Known classes receive per-class
// vtables with desktop-safe defaults; unknown classes still receive a logged generic object whose
// methods return E_NOTIMPL. No Microsoft implementation code is used.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <string>
#include <utility>

namespace {
constexpr HRESULT not_implemented = static_cast<HRESULT>(0x80004001u);
constexpr std::size_t slot_count = 256;

constexpr GUID zero_guid = {};
constexpr GUID threading_class = {0x073b7dcb, 0x1fcf, 0x4030,
                                  {0x94, 0xbe, 0xe3, 0xc9, 0xeb, 0x62, 0x34, 0x28}};
constexpr GUID networking_class = {0x37e56907, 0x2f10, 0x41e8,
                                   {0xb7, 0x2f, 0x36, 0xed, 0xb1, 0x85, 0x33, 0x1a}};
constexpr GUID networking_interface = {0xbf2346b2, 0x39af, 0x4658,
                                       {0xb5, 0xea, 0x44, 0x71, 0x3c, 0x7e, 0x83, 0xb3}};
constexpr GUID user_class = {0x01acd177, 0x91f9, 0x4763,
                             {0xa3, 0x8e, 0xcc, 0xbb, 0x55, 0xce, 0x32, 0xe0}};
constexpr GUID persistent_local_storage_class = {0xf4faf4d4, 0x2d04, 0x4fce,
                                                 {0xb3, 0xe0, 0x47, 0x4a, 0x71, 0x3a, 0x3e, 0x84}};
constexpr GUID persistent_local_storage_interface = {0x41a4e10c, 0x5a7e, 0x41d9,
                                                     {0x8c, 0x37, 0x37, 0xbd, 0xe6, 0x2a, 0x07, 0xd6}};
constexpr GUID display_class = {0x03f0fe74, 0xfdd9, 0x4e5c,
                                {0xb6, 0x30, 0xf9, 0x33, 0x9c, 0x47, 0xac, 0xc5}};
constexpr GUID display_interface = {0x35f07670, 0x706e, 0x4bfb,
                                    {0x94, 0x76, 0x09, 0x07, 0x98, 0xc5, 0xeb, 0xf3}};

constexpr std::uint32_t networking_level_internet_access = 3;
constexpr std::uint32_t networking_cost_unrestricted = 1;
constexpr std::uint32_t user_state_signed_in = 0;
constexpr std::uint32_t user_age_group_adult = 3;
constexpr std::uint64_t synthetic_user_local_id = 1;
constexpr std::uint64_t synthetic_user_id = 1;
constexpr std::uint32_t synthetic_max_users = 1;
constexpr std::uint32_t display_hdr_disabled = 2;

struct connectivity_hint {
    std::uint32_t connectivity_level;
    std::uint32_t connectivity_cost;
    std::uint32_t iana_interface_type;
    std::uint8_t network_initialized;
    std::uint8_t approaching_data_limit;
    std::uint8_t over_data_limit;
    std::uint8_t roaming;
};
static_assert(sizeof(connectivity_hint) == 16, "XNetworkingConnectivityHint layout");

enum class class_kind {
    generic,
    threading,
    networking,
    user,
    persistent_local_storage,
    display,
};

struct class_descriptor;

struct shim_object {
    void** vtable = nullptr;
    const class_descriptor* desc = nullptr;
    std::atomic<ULONG> refs{0};
};

struct class_descriptor {
    GUID class_id{};
    GUID interface_id{};
    bool has_interface_id = false;
    const wchar_t* name = L"";
    class_kind kind = class_kind::generic;
    void** vtable = nullptr;
    shim_object object{};
};

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

void format_guid(wchar_t (&buffer)[40], const GUID* id)
{
    if (id == nullptr) {
        wcscpy_s(buffer, L"null");
        return;
    }
    swprintf_s(buffer, _countof(buffer), L"{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
               id->Data1, id->Data2, id->Data3, id->Data4[0], id->Data4[1], id->Data4[2],
               id->Data4[3], id->Data4[4], id->Data4[5], id->Data4[6], id->Data4[7]);
}

bool same_guid(const GUID& left, const GUID& right)
{
    return std::memcmp(&left, &right, sizeof(GUID)) == 0;
}

void log_object(const wchar_t* event, const shim_object* self)
{
    wchar_t class_text[40] = L"unknown";
    wchar_t interface_text[40] = L"none";
    const wchar_t* name = L"unknown";
    if (self != nullptr && self->desc != nullptr) {
        format_guid(class_text, &self->desc->class_id);
        if (self->desc->has_interface_id) format_guid(interface_text, &self->desc->interface_id);
        name = self->desc->name;
    }
    log_line(L"%s class=%s name=%s iid=%s self=%p", event, class_text, name, interface_text,
             static_cast<const void*>(self));
}

void log_method(const shim_object* self, std::size_t slot, const wchar_t* method_name,
                std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d,
                std::uint64_t e)
{
    wchar_t class_text[40] = L"unknown";
    wchar_t interface_text[40] = L"none";
    const wchar_t* name = L"unknown";
    if (self != nullptr && self->desc != nullptr) {
        format_guid(class_text, &self->desc->class_id);
        if (self->desc->has_interface_id) format_guid(interface_text, &self->desc->interface_id);
        name = self->desc->name;
    }
    log_line(L"method class=%s name=%s iid=%s slot=%zu method_name=%s self=%p a=%016llx b=%016llx "
             L"c=%016llx d=%016llx e=%016llx",
             class_text, name, interface_text, slot, method_name, static_cast<const void*>(self),
             static_cast<unsigned long long>(a), static_cast<unsigned long long>(b),
             static_cast<unsigned long long>(c), static_cast<unsigned long long>(d),
             static_cast<unsigned long long>(e));
}

ULONG STDMETHODCALLTYPE shim_add_ref(shim_object* self)
{
    if (self == nullptr) return 0;
    ULONG count = self->refs.fetch_add(1, std::memory_order_relaxed) + 1;
    log_object(L"AddRef", self);
    log_line(L"AddRef refs=%lu", static_cast<unsigned long>(count));
    return count;
}

ULONG STDMETHODCALLTYPE shim_release(shim_object* self)
{
    if (self == nullptr) return 0;
    ULONG count = self->refs.load(std::memory_order_relaxed);
    while (count != 0) {
        if (self->refs.compare_exchange_weak(count, count - 1, std::memory_order_relaxed)) {
            --count;
            break;
        }
    }
    log_object(L"Release", self);
    log_line(L"Release refs=%lu", static_cast<unsigned long>(count));
    return count;
}

HRESULT STDMETHODCALLTYPE shim_query_interface(shim_object* self, const GUID* interface_id,
                                               void** out)
{
    if (out == nullptr) return E_POINTER;
    *out = nullptr;
    if (self == nullptr) return E_POINTER;
    log_object(L"QueryInterface", self);
    log_guid(L"object QueryInterface iid", interface_id);
    *out = self;
    shim_add_ref(self);
    return S_OK;
}

const std::wstring& persistent_storage_path_w()
{
    static const std::wstring path = [] {
        std::wstring result;
        wchar_t base[MAX_PATH] = {};
        DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
        if (length > 0 && length < MAX_PATH) {
            result.assign(base, length);
        } else {
            wchar_t temp[MAX_PATH] = {};
            DWORD temp_length = GetTempPathW(MAX_PATH, temp);
            if (temp_length > 0 && temp_length < MAX_PATH) {
                result.assign(temp, temp_length);
            } else {
                result = L".";
            }
        }
        if (!result.empty() && result.back() != L'\\' && result.back() != L'/') {
            result.push_back(L'\\');
        }
        result += L"Xbox2Windows\\PersistentLocalStorage";
        for (std::size_t index = 1; index < result.size(); ++index) {
            if (result[index] == L'\\' || result[index] == L'/') {
                const wchar_t separator = result[index];
                result[index] = L'\0';
                CreateDirectoryW(result.c_str(), nullptr);
                result[index] = separator;
            }
        }
        CreateDirectoryW(result.c_str(), nullptr);
        return result;
    }();
    return path;
}

std::string wide_to_utf8(const std::wstring& text)
{
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                         static_cast<int>(text.size()), nullptr, 0, nullptr,
                                         nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), &result[0], size,
                        nullptr, nullptr);
    return result;
}

const std::string& persistent_storage_path_utf8()
{
    static const std::string path = wide_to_utf8(persistent_storage_path_w());
    return path;
}

template <class_kind Kind, std::size_t Slot>
constexpr const wchar_t* slot_name()
{
    if constexpr (Kind == class_kind::threading) {
        if constexpr (Slot == 24) return L"XThreadSetTimeSensitive";
        if constexpr (Slot == 25) return L"XTaskQueueIsEmpty";
        if constexpr (Slot == 26) return L"XThreadAssertNotTimeSensitive";
        if constexpr (Slot == 27) return L"XThreadIsTimeSensitive";
    } else if constexpr (Kind == class_kind::networking) {
        if constexpr (Slot == 0) return L"XNetworkingQueryPreferredLocalUdpMultiplayerPort";
        if constexpr (Slot == 3) return L"XNetworkingRegisterPreferredLocalUdpMultiplayerPortChanged";
        if constexpr (Slot == 4) return L"XNetworkingUnregisterPreferredLocalUdpMultiplayerPortChanged";
        if constexpr (Slot == 12) return L"XNetworkingGetConnectivityHint";
        if constexpr (Slot == 13) return L"XNetworkingRegisterConnectivityHintChanged";
        if constexpr (Slot == 14) return L"XNetworkingUnregisterConnectivityHintChanged";
        if constexpr (Slot == 15) return L"XNetworkingQueryConfigurationSetting";
        if constexpr (Slot == 16) return L"XNetworkingSetConfigurationSetting";
        if constexpr (Slot == 17) return L"XNetworkingQueryStatistics";
    } else if constexpr (Kind == class_kind::user) {
        if constexpr (Slot == 0) return L"XUserDuplicateHandle";
        if constexpr (Slot == 1) return L"XUserCloseHandle";
        if constexpr (Slot == 2) return L"XUserCompare";
        if constexpr (Slot == 3) return L"XUserGetMaxUsers";
        if constexpr (Slot == 4) return L"XUserAddAsync";
        if constexpr (Slot == 5) return L"XUserAddResult";
        if constexpr (Slot == 6) return L"XUserGetLocalId";
        if constexpr (Slot == 7) return L"XUserFindUserByLocalId";
        if constexpr (Slot == 8) return L"XUserGetId";
        if constexpr (Slot == 9) return L"XUserFindUserById";
        if constexpr (Slot == 10) return L"XUserGetIsGuest";
        if constexpr (Slot == 11) return L"XUserGetState";
        if constexpr (Slot == 16) return L"XUserGetAgeGroup";
        if constexpr (Slot == 17) return L"XUserCheckPrivilege";
        if constexpr (Slot == 30) return L"XUserRegisterForChangeEvent";
        if constexpr (Slot == 31) return L"XUserUnregisterForChangeEvent";
        if constexpr (Slot == 32) return L"XUserGetSignOutDeferral";
        if constexpr (Slot == 33) return L"XUserCloseSignOutDeferralHandle";
    } else if constexpr (Kind == class_kind::persistent_local_storage) {
        if constexpr (Slot == 0) return L"XPersistentLocalStorageGetPathSize";
        if constexpr (Slot == 1) return L"XPersistentLocalStorageGetPath";
    } else if constexpr (Kind == class_kind::display) {
        if constexpr (Slot == 1) return L"XDisplayTryEnableHdrMode";
    }
    return L"";
}

template <class_kind Kind, std::size_t Slot>
HRESULT apply_policy(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d,
                     std::uint64_t e)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    if constexpr (Kind == class_kind::threading) {
        if constexpr (Slot == 24) {
            log_line(L"XThreadSetTimeSensitive: desktop no-op");
            return S_OK;
        } else if constexpr (Slot == 25) {
            log_line(L"XTaskQueueIsEmpty: reporting empty (no desktop task queue)");
            return static_cast<HRESULT>(1);
        } else if constexpr (Slot == 26) {
            log_line(L"XThreadAssertNotTimeSensitive: safe no-op");
            return S_OK;
        } else if constexpr (Slot == 27) {
            log_line(L"XThreadIsTimeSensitive: reporting false");
            return S_OK;
        } else {
            return not_implemented;
        }
    } else if constexpr (Kind == class_kind::networking) {
        if constexpr (Slot == 0) {
            if (a != 0) *reinterpret_cast<std::uint16_t*>(a) = 0;
            log_line(L"XNetworkingQueryPreferredLocalUdpMultiplayerPort: returning ephemeral port 0");
            return S_OK;
        } else if constexpr (Slot == 3) {
            if (d != 0) *reinterpret_cast<std::uint64_t*>(d) = 0;
            log_line(L"XNetworkingRegisterPreferredLocalUdpMultiplayerPortChanged: registered no-op "
                     L"token=0");
            return S_OK;
        } else if constexpr (Slot == 4) {
            log_line(L"XNetworkingUnregisterPreferredLocalUdpMultiplayerPortChanged: no callbacks "
                     L"registered");
            return static_cast<HRESULT>(1);
        } else if constexpr (Slot == 12) {
            if (a != 0) {
                connectivity_hint hint{};
                hint.connectivity_level = networking_level_internet_access;
                hint.connectivity_cost = networking_cost_unrestricted;
                hint.iana_interface_type = 0;
                hint.network_initialized = 1;
                hint.approaching_data_limit = 0;
                hint.over_data_limit = 0;
                hint.roaming = 0;
                std::memcpy(reinterpret_cast<void*>(a), &hint, sizeof(hint));
                log_line(L"XNetworkingGetConnectivityHint: desktop default InternetAccess/Unrestricted "
                         L"initialized=1");
            } else {
                log_line(L"XNetworkingGetConnectivityHint: null output pointer");
            }
            return S_OK;
        } else if constexpr (Slot == 13) {
            if (d != 0) *reinterpret_cast<std::uint64_t*>(d) = 0;
            log_line(L"XNetworkingRegisterConnectivityHintChanged: registered no-op token=0");
            return S_OK;
        } else if constexpr (Slot == 14) {
            log_line(L"XNetworkingUnregisterConnectivityHintChanged: no callbacks registered");
            return static_cast<HRESULT>(1);
        } else if constexpr (Slot == 15) {
            if (b != 0) *reinterpret_cast<std::uint64_t*>(b) = 0;
            log_line(L"XNetworkingQueryConfigurationSetting: returning zero default");
            return S_OK;
        } else if constexpr (Slot == 16) {
            log_line(L"XNetworkingSetConfigurationSetting: desktop no-op");
            return S_OK;
        } else if constexpr (Slot == 17) {
            log_line(L"XNetworkingQueryStatistics: statistics layout unsupported on desktop");
            return not_implemented;
        }
        return not_implemented;
    } else if constexpr (Kind == class_kind::user) {
        if constexpr (Slot == 0) {
            if (b != 0) *reinterpret_cast<void**>(b) = reinterpret_cast<void*>(a);
            return S_OK;
        } else if constexpr (Slot == 1) {
            return S_OK;
        } else if constexpr (Slot == 2) {
            return static_cast<HRESULT>(a == b ? 0 : 1);
        } else if constexpr (Slot == 3) {
            if (a != 0) *reinterpret_cast<std::uint32_t*>(a) = synthetic_max_users;
            return S_OK;
        } else if constexpr (Slot == 4 || Slot == 5) {
            log_line(L"XUserAddAsync/AddResult: asynchronous desktop sign-in is unsupported");
            return not_implemented;
        } else if constexpr (Slot == 6) {
            if (b != 0) *reinterpret_cast<std::uint64_t*>(b) = synthetic_user_local_id;
            return S_OK;
        } else if constexpr (Slot == 7 || Slot == 9) {
            log_line(L"XUserFindUserBy*: no synthetic user registry on desktop");
            return not_implemented;
        } else if constexpr (Slot == 8) {
            if (b != 0) *reinterpret_cast<std::uint64_t*>(b) = synthetic_user_id;
            return S_OK;
        } else if constexpr (Slot == 10) {
            if (b != 0) *reinterpret_cast<std::uint8_t*>(b) = 0;
            return S_OK;
        } else if constexpr (Slot == 11) {
            if (b != 0) *reinterpret_cast<std::uint32_t*>(b) = user_state_signed_in;
            return S_OK;
        } else if constexpr (Slot == 12) {
            return not_implemented;
        } else if constexpr ((Slot >= 13 && Slot <= 15) || (Slot >= 18 && Slot <= 29)) {
            log_line(L"XUser async/result method slot=%zu: unsupported on desktop", Slot);
            return not_implemented;
        } else if constexpr (Slot == 16) {
            if (b != 0) *reinterpret_cast<std::uint32_t*>(b) = user_age_group_adult;
            return S_OK;
        } else if constexpr (Slot == 17) {
            if (d != 0) *reinterpret_cast<std::uint8_t*>(d) = 1;
            if (e != 0) *reinterpret_cast<std::uint32_t*>(e) = 0;
            log_line(L"XUserCheckPrivilege: granting privileges for the synthetic desktop user");
            return S_OK;
        } else if constexpr (Slot == 30) {
            if (d != 0) *reinterpret_cast<std::uint64_t*>(d) = 0;
            log_line(L"XUserRegisterForChangeEvent: registered no-op token=0");
            return S_OK;
        } else if constexpr (Slot == 31) {
            return S_OK;
        } else if constexpr (Slot == 32) {
            if (a != 0) *reinterpret_cast<void**>(a) = nullptr;
            log_line(L"XUserGetSignOutDeferral: returning null deferral");
            return S_OK;
        } else if constexpr (Slot == 33) {
            return S_OK;
        } else {
            return not_implemented;
        }
    } else if constexpr (Kind == class_kind::persistent_local_storage) {
        if constexpr (Slot == 0) {
            if (a != 0) {
                *reinterpret_cast<std::size_t*>(a) = persistent_storage_path_utf8().size() + 1;
            }
            return S_OK;
        } else if constexpr (Slot == 1) {
            const std::string& path = persistent_storage_path_utf8();
            const std::size_t required = path.size() + 1;
            if (a == 0 || b == 0) {
                log_line(L"XPersistentLocalStorageGetPath: null buffer or zero size");
                return E_POINTER;
            }
            if (a < required) {
                log_line(L"XPersistentLocalStorageGetPath: buffer too small need=%zu got=%zu",
                         required, static_cast<std::size_t>(a));
                return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
            }
            std::memcpy(reinterpret_cast<void*>(b), path.c_str(), required);
            if (c != 0) *reinterpret_cast<std::size_t*>(c) = required;
            log_line(L"XPersistentLocalStorageGetPath: returned %s",
                     persistent_storage_path_w().c_str());
            return S_OK;
        } else {
            return not_implemented;
        }
    } else if constexpr (Kind == class_kind::display) {
        if constexpr (Slot == 1) {
            log_line(L"XDisplayTryEnableHdrMode: S_OK, result Disabled on desktop");
            if (b) *reinterpret_cast<std::uint32_t*>(b) = display_hdr_disabled;
            return S_OK;
        } else {
            return not_implemented;
        }
    } else {
        return not_implemented;
    }
}

template <class_kind Kind, std::size_t Slot>
HRESULT STDMETHODCALLTYPE dispatch_slot(shim_object* self, std::uint64_t a, std::uint64_t b,
                                        std::uint64_t c, std::uint64_t d, std::uint64_t e)
{
    log_method(self, Slot, slot_name<Kind, Slot>(), a, b, c, d, e);
    return apply_policy<Kind, Slot>(a, b, c, d, e);
}

template <class_kind Kind, std::size_t... I>
std::array<void*, 3 + sizeof...(I)> make_class_vtable(std::index_sequence<I...>)
{
    return {reinterpret_cast<void*>(&shim_query_interface),
            reinterpret_cast<void*>(&shim_add_ref), reinterpret_cast<void*>(&shim_release),
            reinterpret_cast<void*>(&dispatch_slot<Kind, I>)...};
}

template <class_kind Kind>
void** class_vtable()
{
    static std::array<void*, 3 + slot_count> table =
        make_class_vtable<Kind>(std::make_index_sequence<slot_count>{});
    return table.data();
}

struct descriptor_seed {
    const GUID* class_id;
    const GUID* interface_id;
    const wchar_t* name;
};

template <class_kind Kind>
class_descriptor& registered_descriptor(descriptor_seed seed)
{
    static class_descriptor descriptor;
    static const bool initialized = [seed] {
        descriptor.class_id = *seed.class_id;
        if (seed.interface_id != nullptr) {
            descriptor.interface_id = *seed.interface_id;
            descriptor.has_interface_id = true;
        }
        descriptor.name = seed.name;
        descriptor.kind = Kind;
        descriptor.vtable = class_vtable<Kind>();
        descriptor.object.vtable = descriptor.vtable;
        descriptor.object.desc = &descriptor;
        return true;
    }();
    (void)initialized;
    return descriptor;
}

class_descriptor& generic_descriptor()
{
    return registered_descriptor<class_kind::generic>({&zero_guid, nullptr, L"Generic"});
}

bool is_known_class(const GUID* class_id)
{
    return class_id != nullptr &&
           (same_guid(*class_id, threading_class) || same_guid(*class_id, networking_class) ||
            same_guid(*class_id, user_class) ||
            same_guid(*class_id, persistent_local_storage_class) ||
            same_guid(*class_id, display_class));
}

class_descriptor& descriptor_for_class(const GUID* class_id)
{
    if (class_id != nullptr) {
        if (same_guid(*class_id, threading_class)) {
            return registered_descriptor<class_kind::threading>(
                {&threading_class, &threading_class, L"XThreadingImpl"});
        }
        if (same_guid(*class_id, networking_class)) {
            return registered_descriptor<class_kind::networking>(
                {&networking_class, &networking_interface, L"XNetworkingImpl2"});
        }
        if (same_guid(*class_id, user_class)) {
            return registered_descriptor<class_kind::user>(
                {&user_class, &user_class, L"XUserImpl"});
        }
        if (same_guid(*class_id, persistent_local_storage_class)) {
            return registered_descriptor<class_kind::persistent_local_storage>(
                {&persistent_local_storage_class, &persistent_local_storage_interface,
                 L"XPersistentLocalStorageImpl"});
        }
        if (same_guid(*class_id, display_class)) {
            return registered_descriptor<class_kind::display>(
                {&display_class, &display_interface, L"XDisplayImpl"});
        }
    }
    return generic_descriptor();
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
    *out = nullptr;
    class_descriptor& descriptor = descriptor_for_class(class_id);
    if (descriptor.has_interface_id && interface_id != nullptr &&
        !same_guid(*interface_id, descriptor.interface_id)) {
        log_line(L"QueryApiImpl: iid mismatch for class=%s; returning the class object",
                 descriptor.name);
    }
    if (!is_known_class(class_id)) {
        log_line(L"QueryApiImpl: unknown class -> generic object");
    }
    shim_object* object = &descriptor.object;
    object->refs.fetch_add(1, std::memory_order_relaxed);
    *out = object;
    log_line(L"QueryApiImpl -> name=%s self=%p", descriptor.name,
             static_cast<const void*>(object));
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
