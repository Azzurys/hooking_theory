#include <iostream>
#include <windows.h>
#include "detour.hpp"


int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }

void MessageBoxHook()
{
    std::cout << "MessageBoxA hijacked !" << std::endl;
}

BOOL CursorPosHook(LPPOINT point)
{
    point->x = 0xDEAD;
    point->y = 0xBEEF;

    return true;
}

int main()
{
    // regular function hooking
    {
        std::cout << add(10, 10) << std::endl;   // 20

        detour_hook detour((void*)add, (void*)sub);

        detour.install();
        std::cout << add(10, 10) << std::endl;   // 0
        detour.uninstall();

        std::cout << add(10, 10) << std::endl;   // 20
    }

    // winapi hooking
    {
        detour_hook detour("MessageBoxA", "user32.dll", (void *) MessageBoxHook);
        detour.install();
        MessageBoxA(nullptr, "Text", "Caption", MB_OK);
    }

    // intercepting target parameters
    {
        detour_hook detour("GetCursorPos", "user32.dll", (void *) CursorPosHook);
        detour.install();

        POINT point;
        GetCursorPos(&point);

        std::cout << std::hex << point.x << ' ' << point.y << std::endl;
    }

    return 0;
}
