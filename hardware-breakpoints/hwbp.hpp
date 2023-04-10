#ifndef HWBP_HPP
#define HWBP_HPP

#include <vector>
#include <windows.h>


namespace details
{
    LONG exception_filter(PEXCEPTION_POINTERS);
}

class breakpoints
{
private:
    struct hook_entry
    {
        uint64_t targ = 0;
        uint64_t stub = 0;
    };

    inline static std::vector<hook_entry> hooks {};
    inline static bool initialized = false;

private:
    static void update_breakpoints()
    {
        CONTEXT context;
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        HANDLE hThread = GetCurrentThread();

        if (GetThreadContext(hThread, &context))
        {
            /* Sets debug registers Dr0-Dr3, holding the breakpoints addresses */
            for (auto i = 0; i < hooks.size(); ++i)
                *(&context.Dr0 + sizeof(DWORD64) * i) = hooks[i].targ;

            /*
             * The debug control register (Dr7) is used to selectively enable
             * the four address breakpoint conditions, and to specify the type
             * and size of each of the four breakpoints.
             *
             * We set bits 1, 2, 4, and 6 to enable breakpoints locally (current task only)
             * We leave the others bits to 0 because we want to break on instruction execution only
             */
            context.Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);

            SetThreadContext(hThread, &context);
        }
    }

public:
    static void init()
    {
        hooks.reserve(4);

        // triggered once we hit breakpoints
        SetUnhandledExceptionFilter(details::exception_filter);

        initialized = true;
    }

    static const std::vector<hook_entry>& entries()
    {
        return hooks;
    }

    static void register_entry(void* targ, void* stub)
    {
        if (!initialized)
            init();

        if (hooks.size() >= 4)
            throw std::runtime_error("Already registered the maximum breakpoint amount");

        if (!targ || !stub)
            throw std::runtime_error("Can't register null hook");

        hook_entry entry = {
            .targ = (uint64_t)targ,
            .stub = (uint64_t)stub
        };

        hooks.push_back(entry);

        update_breakpoints();
    }
};

namespace details
{
    LONG exception_filter(PEXCEPTION_POINTERS exception)
    {
        const auto code = exception->ExceptionRecord->ExceptionCode;
        const auto addr = exception->ExceptionRecord->ExceptionAddress;

        if (code == EXCEPTION_SINGLE_STEP || code == EXCEPTION_BREAKPOINT)
        {
            for (const auto [targ, stub] : breakpoints::entries())
            {
                if (targ == (uint64_t)addr)
                {
                    exception->ContextRecord->Rip = stub;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }
}


#endif // HWBP_HPP