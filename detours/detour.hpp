#ifndef HOOKS_DETOUR_HPP
#define HOOKS_DETOUR_HPP

#include <string>
#include <array>
#include <windows.h>
#include <cstdint>
#include <stdexcept>


namespace
{
#pragma pack(push, 1)
   struct patch_t
   {
       const uint16_t mov = 0xB848;        // mov rax, val opcode
       const uint64_t val;                 // val being the detour function address
       const uint16_t jmp = 0xE0FF;        // jmp rax opcode
   };
#pragma pack(pop)

    constexpr size_t PATCH_SIZE = sizeof(patch_t);

    void memrd(void* addr, char* buffer,    size_t len) { memcpy(buffer, addr, len); }
    void memwr(void* addr, const char* src, size_t len) { memcpy(addr, src, len);    }
}

class detour_hook
{
public:
    detour_hook(void* target, void* detour) : target(target), detour(detour) {}

    detour_hook(const std::string& target_sym, const std::string& module, void* detour) : detour(detour)
    {
        const HMODULE handle = GetModuleHandleA(module.c_str());

        if (!handle)
            throw std::runtime_error("Couldn't retrieve handle for module " + module);

        const FARPROC tmp = GetProcAddress(handle, target_sym.c_str());

        if (!tmp)
            throw std::runtime_error("Couldn't retrieve address of symbol " + target_sym + " from module " + module);

        target = reinterpret_cast<void*>(tmp);
    }

    ~detour_hook()
    {
        if (installed)
            uninstall();
    }

    void install()
    {
        if (!target || !detour)
            throw std::runtime_error("Invalid function or detour_hook");

        if (installed)
            return;

        const patch_t payload = { .val = (uint64_t)detour };

        DWORD prot_flags;
        VirtualProtect(target, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &prot_flags);

        memrd(target, code_backup.data(), PATCH_SIZE);                    // save original bytes
        memwr(target, reinterpret_cast<const char*>(&payload), PATCH_SIZE);  // write our patch

        VirtualProtect(target, PATCH_SIZE, prot_flags, &prot_flags);

        installed = true;
    }

    void uninstall()
    {
        if (!installed)
            throw std::runtime_error("Trying to unhook a function that was not hooked yet");

        DWORD prot_flags;
        VirtualProtect(target, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &prot_flags);

        memwr(target, code_backup.data(), PATCH_SIZE);

        VirtualProtect(target, PATCH_SIZE, prot_flags, &prot_flags);

        installed = false;
    }


private:
    bool installed = false;

    void* target;
    void* detour;

    std::array<char, PATCH_SIZE> code_backup {};
};

#endif //HOOKS_DETOUR_HPP
