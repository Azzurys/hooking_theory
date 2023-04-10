#include <iostream>
#include <memory>

#include <Windows.h>


template<typename Object, typename Stub>
void vmt_hook(Object* instance, Stub stub, int offset)
{
    const uintptr_t vmt_base  = *((uintptr_t*)instance);
    const uintptr_t vmt_entry = vmt_base + sizeof(uintptr_t) * offset;

    DWORD pr_flags;
    VirtualProtect((LPVOID)vmt_entry, 4096, PAGE_READWRITE, &pr_flags);
    *((uintptr_t*)vmt_entry) = (uintptr_t)stub;
    VirtualProtect((LPVOID)vmt_entry, 4096, pr_flags, &pr_flags);
}


struct object
{
    int value { 1337 };

    object() = default;
    ~object() = default;

    virtual void member1() const { std::cout << "object::member1() called" << std::endl; }
    virtual void member2() const { std::cout << "object::member2() called" << std::endl; }
};


void member1_stub(object* instance [[maybe_unused]])
{
    std::cout << "object::member1() call redirected to hook stub" << std::endl;
}

void member2_stub(object* instance)
{
    instance->value = 0xDEAD;
}

int main()
{
    std::cout << std::hex;

    const auto obj = std::make_unique<object>();

    obj->member1();
    obj->member2();
    std::cout << obj->value << std::endl;

    vmt_hook(obj.get(), member1_stub, 0);
    vmt_hook(obj.get(), member2_stub, 1);

    obj->member1();
    obj->member2();
    std::cout << obj->value << std::endl;

    return 0;
}





