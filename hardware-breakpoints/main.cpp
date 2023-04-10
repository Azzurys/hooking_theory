#include <iostream>
#include <thread>
#include "hwbp.hpp"


bool is_superuser()
{
    // ...

    return false;
}

int main()
{
    using namespace std::chrono_literals;

    // pretend this gets called from a malicious DLL
    breakpoints::register_entry((void*)is_superuser, (void*)[] { return true; });

    for (volatile const bool su = is_superuser(); !su;)
    {
        std::cout << "not superuser" << std::endl;
        std::this_thread::sleep_for(500ms);

    }

    std::cout << "superuser ???" << std::endl;

    return EXIT_SUCCESS;
}
