# cpuinfo
A C++ class for runtime feature detection

The `CpuInfo` class provides comprehensive feature detection for x86 processors, allowing code to detect features at runtime instead of compile-time.

### Usage

Create a `CpuInfo` instance without parameters, then just request features, and detection will occur behind the scenes.

    CpuInfo info;
    if (info.feature_AVX_supported())
        std::cout << "AVX is supported\n";
        
The `valid()` function allows you to check whether the class encountered an error (it is `false` if an error arose).
        
Or, lower level access allows you to create an instance with parameters to send to the `CPUID` instruction, and directly access the results:

    CpuInfo info(0);
    std::cout << "EAX: " << info.eax() << "\n";
    std::cout << "EBX: " << info.ebx() << "\n";
    std::cout << "ECX: " << info.ecx() << "\n";
    std::cout << "EDX: " << info.edx() << "\n";
    
You can also use the `get()` function to create low-level `CPUID` requests.
    
All functions should return an empty string, `false`, or 0 if `valid()` returns `false`.

An example of how to use `CpuInfo` in the wild as a POPCNT dispatcher:

    #include "cpuinfo.h"
    #include <mutex>
    #include <atomic>

    template<typename T>
    unsigned int popcnt_naive(T value) {
        static_assert(!std::numeric_limits<T>::is_signed, "popcnt_naive() requires an unsigned integral type");

        unsigned int c = 0;
        for (; value; ++c)
            value &= value - 1;
        return c;
    }

    template<typename T>
    unsigned int popcnt_intrinsic(T value) {return popcnt_naive(value);}

    template<>
    unsigned int popcnt_intrinsic<uint16_t>(uint16_t value) {
    #if MSVC_COMPILER
        return __popcnt16(value);
    #elif GCC_COMPILER | CLANG_COMPILER
        return __builtin_popcountl(value);
    #else
        return popcnt_naive(value);
    #endif
    }

    template<>
    unsigned int popcnt_intrinsic<uint32_t>(uint32_t value) {
    #if MSVC_COMPILER
        return __popcnt(value);
    #elif GCC_COMPILER | CLANG_COMPILER
        return __builtin_popcountl(value);
    #else
        return popcnt_naive(value);
    #endif
    }

    template<>
    unsigned int popcnt_intrinsic<uint64_t>(uint64_t value) {
    #if MSVC_COMPILER
        return unsigned(__popcnt64(value));
    #elif GCC_COMPILER | CLANG_COMPILER
        return __builtin_popcountll(value);
    #else
        return popcnt_naive(value);
    #endif
    }

    template<typename T>
    unsigned int popcnt(T value) {
        static std::atomic<unsigned int (*)(T)> popcnt_impl;

        // If not already detected...
        if (!popcnt_impl.load()) {
            // Try to determine supported implementation
            CpuInfo info;
            if (info.feature_POPCNT_supported() && info.valid())
                popcnt_impl.store(popcnt_intrinsic<T>);
            else
                popcnt_impl.store(popcnt_naive<T>);
        }

        return (*popcnt_impl.load())(value);
    }
