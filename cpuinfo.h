#ifndef GENERIC_CPUID_H
#define GENERIC_CPUID_H

#define CLANG_COMPILER (defined(__clang__) & !defined(__GNUC__))
#define GCC_COMPILER (defined(__GNUC__) & !defined(__clang__))
#ifdef _MSC_VER
#define MSVC_COMPILER 1
#else
#define MSVC_COMPILER 0
#endif

#if (defined(__alpha__) | defined(__alpha) | defined(_M_ALPHA))
#define ALPHA_CPU 1
#else
#define ALPHA_CPU 0
#endif

#if (defined(__amd64__) | defined(__amd64) | defined(__x86_64__) | defined(__x86_64) | defined(_M_AMD64))
#define AMD64_CPU 1
#else
#define AMD64_CPU 0
#endif

#if (defined(__arm__) | defined(__thumb__) | defined(__TARGET_ARCH_ARM) | defined(__TARGET_ARCH_THUMB) | defined(_ARM) | defined(_M_ARM) | defined(_M_ARMT) | defined(__arm))
#define ARM_CPU 1
#else
#define ARM_CPU 0
#endif

#if (defined(__aarch64__))
#define ARM64_CPU 1
#else
#define ARM64_CPU 0
#endif

#if (defined(__bfin) | defined(__BFIN__))
#define BLACKFIN_CPU 1
#else
#define BLACKFIN_CPU 0
#endif

#if (defined(__convex__))
#define CONVEX_CPU 1
#else
#define CONVEX_CPU 0
#endif

#if (defined(__epiphany__))
#define EPIPHANY_CPU 1
#else
#define EPIPHANY_CPU 0
#endif

#if (defined(__hppa__) | defined(__HPPA__) | defined(__hppa))
#define HPPA_RISC_CPU 1
#else
#define HPPA_RISC_CPU 0
#endif

#if (defined(i386) | defined(__i386) | defined(__i386__) | defined(__i486__) | defined(__i586__) | defined(__i686__) | defined(__IA32__) | \
     defined(_M_I86) | defined(_M_IX86) | defined(__X86__) | defined(_X86_) | defined(__THW_INTEL__) | defined(__I86__) | defined(__INTEL__) | defined(__386))
#define X86_CPU 1
#else
#define X86_CPU 0
#endif

#if (defined(__ia64__) | defined(_IA64) | defined(__IA64__) | defined(__ia64) | defined(_M_IA64) | defined(__itanium__))
#define ITANIUM_CPU 1
#else
#define ITANIUM_CPU 0
#endif

#if (defined(__m68k__) | defined(M68000) | defined(__MC68K__))
#define M68K_CPU 1
#else
#define M68K_CPU 0
#endif

#if (defined(__mips__) | defined(mips) | defined(__mips) | defined(__MIPS__))
#define MIPS_CPU 1
#else
#define MIPS_CPU 0
#endif

#if (defined(__powerpc) | defined(__powerpc__) | defined(__powerpc64__) | defined(__POWERPC__) | defined(__ppc__) | defined(__ppc64__) | \
     defined(__PPC__) | defined(__PPC64__) | defined(_ARCH_PPC) | defined(_ARCH_PPC64) | defined(_M_PPC) | defined(_ARCH_PPC) | \
     defined(_ARCH_PPC64) | defined(__PPCGECKO__) | defined(__PPCBROADWAY__) | defined(_XENON) | defined(__ppc))
#define POWERPC_CPU 1
#else
#define POWERPC_CPU 0
#endif

#if (defined(pyr))
#define PYRAMID_CPU 1
#else
#define PYRAMID_CPU 0
#endif

#if (defined(__THW_RS6000) | defined(_IBMR2) | defined(_POWER) | defined(_ARCH_PWR) | defined(_ARCH_PWR2) | defined(_ARCH_PWR3) | defined(_ARCH_PWR4))
#define RS6000_CPU 1
#else
#define RS6000_CPU 0
#endif

#if (defined(__sparc__) | defined(__sparc) | defined(__sparc_v8__) | defined(__sparc_v9__) | defined(__sparc_v8) | defined(__sparc_v9))
#define SPARC_CPU 1
#else
#define SPARC_CPU 0
#endif

#if (defined(__sh__) | defined(__sh1__) | defined(__sh2__) | defined(__sh3__) | defined(__sh4__) | defined(__sh5__))
#define SUPERH_CPU 1
#else
#define SUPERH_CPU 0
#endif

#if (defined(__370__) | defined(__THW_370__) | defined(__s390__) | defined(__s390x__) | defined(__zarch__) | defined(__SYSC_ZARCH__))
#define SYSTEMZ_CPU 1
#else
#define SYSTEMZ_CPU 0
#endif

#if (defined(__TMS470__))
#define TMS470_CPU 1
#else
#define TMS470_CPU 0
#endif

#if X86_CPU | AMD64_CPU
# if MSVC_COMPILER
#  include <intrin.h>
# elif GCC_COMPILER | CLANG_COMPILER
#  include <cpuid.h>
#  include <x86intrin.h>
# endif
#elif ARM_CPU | ARM64_CPU
# include <sys/auxv.h>
# include <asm/hwcap.h>
#endif

#include <cstdint>
#include <string>
#include <cstring>

class CpuInfo
{
    uint32_t info[4];
    uint32_t functionID;
    uint32_t subfunctionID;
    bool m_valid;

    bool set_invalid() {
        memset(info, 0, 4 * sizeof(*info));
        return m_valid = false;
    }

    void requires_x86(uint32_t function, uint32_t subfunction = 0) {
#if X86_CPU | AMD64_CPU
        if (!m_valid || function != functionID || subfunction != subfunctionID)
            get(function, subfunction);
#else
        set_invalid();
#endif
    }

    void requires_arm(uint32_t hwcap) {
#if ARM_CPU | ARM64_CPU
        if (!m_valid || hwcap != functionID)
            get_hwcap(hwcap);
#else
        set_invalid();
#endif
    }

#ifndef _XCR_XFEATURE_ENABLED_MASK
#define _XCR_XFEATURE_ENABLED_MASK 0
#endif

    static uint64_t xgetbv(uint32_t xsr) {
#if AMD64_CPU | X86_CPU
#if MSVC_COMPILER
        return _xgetbv(xsr);
#elif GCC_COMPILER | CLANG_COMPILER
        //return _xgetbv(xsr);

        uint32_t hi, lo;
        asm ("xgetbv"
             : "=d" (hi), "=a" (lo)
             : "c" (xsr));

        return (uint64_t(hi) << 32) | lo;
#else
#error no known XGETBV intrinsic exists for this compiler
        return false;
#endif
#else // Non-x86 CPU
        (void) xsr;
        return 0;
#endif
    }

public:
    CpuInfo()
        : functionID(0)
        , subfunctionID(0)
        , m_valid(false)
    {
        memset(info, 0, 4 * sizeof(info[0]));
    }
    CpuInfo(uint32_t function, uint32_t subfunction = 0) {
        get(function, subfunction);
    }

    bool get(uint32_t function, uint32_t subfunction = 0) {
#if AMD64_CPU | X86_CPU
        functionID = function;
        subfunctionID = subfunction;

#if MSVC_COMPILER
        uint32_t tmp_info[4];

        if (function > 0)
        {
            __cpuid(reinterpret_cast<int *>(tmp_info), function & 0x80000000);

            if (tmp_info[0] < function)
            {
                memset(info, 0, 4 * sizeof(*info));
                return m_valid = false;
            }
        }

        __cpuidex(reinterpret_cast<int *>(info), functionID, subfunctionID);

        return m_valid = true;
#elif CLANG_COMPILER | GCC_COMPILER
        unsigned int _eax, _ebx, _ecx, _edx;

        if (function > 0)
        {
            __cpuid(function & 0x80000000, _eax, _ebx, _ecx, _edx);

            if (_eax < function)
            {
                memset(info, 0, 4 * sizeof(*info));
                return m_valid = false;
            }
        }

        __cpuid_count(function, subfunction, info[0], info[1], info[2], info[3]);

        return m_valid = true;
#else
#error no known CPUID intrinsic exists for this compiler
        return false;
#endif
#else // Non-x86 CPU
        (void) function;
        (void) subfunction;
        return set_invalid();
#endif
    }

    bool get_hwcap(uint32_t hwcap) {
#if ARM_CPU | ARM64_CPU
        unsigned long capabilities = getauxval(hwcap);

        functionID = hwcap;

        info[0] = capabilities;
        info[1] = info[2] = info[3] = 0;

        return m_valid = true;
#else
        (void) hwcap;
        return set_invalid();
#endif
    }

    uint32_t eax() const {return m_valid * info[0];}
    uint32_t ebx() const {return m_valid * info[1];}
    uint32_t ecx() const {return m_valid * info[2];}
    uint32_t edx() const {return m_valid * info[3];}

    uint32_t eax(unsigned bit, unsigned length = 1) const {return m_valid * ((info[0] >> bit) & ((1ul << length) - 1));}
    uint32_t ebx(unsigned bit, unsigned length = 1) const {return m_valid * ((info[1] >> bit) & ((1ul << length) - 1));}
    uint32_t ecx(unsigned bit, unsigned length = 1) const {return m_valid * ((info[2] >> bit) & ((1ul << length) - 1));}
    uint32_t edx(unsigned bit, unsigned length = 1) const {return m_valid * ((info[3] >> bit) & ((1ul << length) - 1));}

    uint32_t function() const {return functionID;}
    uint32_t subfunction() const {return subfunctionID;}

    std::string vendor() {
        char vendor_string[16] = {0};

        requires_x86(0);
        *reinterpret_cast<uint32_t *>(vendor_string) = ebx();
        *reinterpret_cast<uint32_t *>(vendor_string + 4) = edx();
        *reinterpret_cast<uint32_t *>(vendor_string + 8) = ecx();

        return vendor_string;
    }

    std::string processor_brand_name() {
        requires_x86(1);

        switch (ebx() & 0xff) {
            default: return "";
            case 0x01: // Fallthrough
            case 0x0A: // Fallthrough
            case 0x14: return "Intel(R) Celeron(R) processor";
            case 0x02: // Fallthrough
            case 0x04: return "Intel(R) Pentium(R) III processor";
            case 0x03: return eax() == 0x000006B1? "Intel(R) Celeron(R) processor": "Intel(R) Pentium(R) III Xeon(R) processor";
            case 0x06: return "Mobile Intel(R) Pentium(R) III processor-M";
            case 0x07: return "Mobile Intel(R) Celeron(R) processor";
            case 0x08: // Fallthrough
            case 0x09: return "Intel(R) Pentium(R) 4 processor";
            case 0x0B: return eax() == 0x00000F13? "Intel(R) Xeon(R) processor MP": "Intel(R) Xeon(R) processor";
            case 0x0C: return "Intel(R) Xeon(R) processor MP";
            case 0x0E: return eax() == 0x00000F13? "Intel(R) Xeon(R) processor": "Mobile Intel(R) Pentium(R) 4 processor-M";
            case 0x0F: // Fallthrough
            case 0x17: return "Mobile Intel(R) Celeron(R) processor";
            case 0x11: // Fallthrough
            case 0x15: return "Mobile Genuine Intel(R) processor";
            case 0x12: return "Intel(R) Celeron(R) M processor";
            case 0x13: return "Mobile Intel(R) Celeron(R) processor";
            case 0x16: return "Intel(R) Pentium(R) M processor";
        }
    }

    uint32_t max_standard_cpuid_leaf() {
        requires_x86(0);
        return eax();
    }
    uint32_t max_extended_cpuid_leaf() {
        requires_x86(0x80000000);
        return eax();
    }

    uint8_t processor_stepping() {
        requires_x86(1);
        return eax(0, 4);
    }
    uint8_t processor_model() {
        requires_x86(1);
        uint16_t family = processor_family();
        if (family == 0x06 || family == 0x0F)
            return (eax(16, 4) << 4) + eax(4, 4);
        return eax(4, 4);
    }
    uint16_t processor_family() {
        requires_x86(1);
        uint16_t temp = eax(8, 4);
        if (temp != 0x0F)
            return temp;
        else
            return temp + eax(20, 8);
    }
    uint8_t processor_type() {
        requires_x86(1);
        return eax(12, 2);
    }

    bool processor_type_is_OEM() {return processor_type() == 0b00;}
    bool processor_type_is_Intel_OverDrive() {return processor_type() == 0b01;}
    bool processor_type_is_Dual() {return processor_type() == 0b10;}
    bool processor_type_is_Intel_reserved() {return processor_type() == 0b11;}

    uint8_t processor_brand_index() {
        requires_x86(1);
        return ebx(0, 8);
    }
    uint16_t processor_cache_line_size() {
        requires_x86(1);
        return ebx(8, 8) * 8;
    }

    bool feature_SSE3_supported_by_processor() {
        requires_x86(1);
        return ecx(0);
    }
    bool feature_SSE3_supported_by_OS() {
        if (!feature_SSE3_supported_by_processor() || !feature_XSAVE_supported_by_OS())
            return false;

        return xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x2;
    }
    bool feature_PCLMULQDQ_supported() {
        requires_x86(1);
        return ecx(1);
    }
    bool feature_64_bit_DS_supported() {
        requires_x86(1);
        return ecx(2);
    }
    bool feature_MONITOR_supported() {
        requires_x86(1);
        return ecx(3);
    }
    bool feature_CPL_qualified_debug_store_supported() {
        requires_x86(1);
        return ecx(4);
    }
    bool feature_VMX_supported() {
        requires_x86(1);
        return ecx(5);
    }
    bool feature_SMX_supported() {
        requires_x86(1);
        return ecx(6);
    }
    bool feature_Intel_SpeedStep_supported() {
        requires_x86(1);
        return ecx(7);
    }
    bool feature_TM2_supported() {
        requires_x86(1);
        return ecx(8);
    }
    bool feature_SSSE3_supported_by_processor() {
        requires_x86(1);
        return ecx(9);
    }
    bool feature_SSSE3_supported_by_OS() {
        if (!feature_SSSE3_supported_by_processor() || !feature_XSAVE_supported_by_OS())
            return false;

        return xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x2;
    }
    bool feature_L1_context_ID_supported() {
        requires_x86(1);
        return ecx(10);
    }
    bool feature_SDBG_supported() {
        requires_x86(1);
        return ecx(11);
    }
    bool feature_FMA3_supported() {
        requires_x86(1);
        return ecx(12);
    }
    bool feature_CMPXCHG16B_supported() {
        requires_x86(1);
        return ecx(13);
    }
    bool feature_xTPR_update_control_supported() {
        requires_x86(1);
        return ecx(14);
    }
    bool feature_PDCM_supported() {
        requires_x86(1);
        return ecx(15);
    }
    bool feature_PCID_supported() {
        requires_x86(1);
        return ecx(17);
    }
    bool feature_DCA_supported() {
        requires_x86(1);
        return ecx(18);
    }
    bool feature_SSE4_1_supported_by_processor() {
        requires_x86(1);
        return ecx(19);
    }
    bool feature_SSE4_1_supported_by_OS() {
        if (!feature_SSE4_1_supported_by_processor() || !feature_XSAVE_supported_by_OS())
            return false;

        return xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x2;
    }
    bool feature_SSE4_2_supported_by_processor() {
        requires_x86(1);
        return ecx(20);
    }
    bool feature_SSE4_2_supported_by_OS() {
        if (!feature_SSE4_2_supported_by_processor() || !feature_XSAVE_supported_by_OS())
            return false;

        return xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x2;
    }
    bool feature_x2APIC_supported() {
        requires_x86(1);
        return ecx(21);
    }
    bool feature_MOVBE_supported() {
        requires_x86(1);
        return ecx(22);
    }
    bool feature_POPCNT_supported() {
        requires_x86(1);
        return ecx(23);
    }
    bool feature_TSC_deadline_supported() {
        requires_x86(1);
        return ecx(24);
    }
    bool feature_AES_supported() {
#if ARM_CPU
        requires_arm(AT_HWCAP2);
        return eax() & HWCAP2_AES;
#elif ARM64_CPU
        requires_arm(AT_HWCAP);
        return eax() & HWCAP_AES;
#else
        requires_x86(1);
        return ecx(25);
#endif
    }
    bool feature_CRC32_supported() {
#if X86_CPU | AMD64_CPU
        return true;
#elif ARM_CPU
        requires_arm(AT_HWCAP2);
        return eax() & HWCAP2_CRC32;
#elif ARM64_CPU
        requires_arm(AT_HWCAP);
        return eax() & HWCAP_CRC32;
#else
        return false;
#endif
    }
    bool feature_PMULL_supported() {
#if ARM_CPU
        requires_arm(AT_HWCAP2);
        return eax() & HWCAP2_PMULL;
#elif ARM64_CPU
        requires_arm(AT_HWCAP);
        return eax() & HWCAP_PMULL;
#else
        return false;
#endif
    }
    bool feature_VFP_supported() {
#if ARM_CPU
        requires_arm(AT_HWCAP);
        return eax() & HWCAP_VFP;
#elif ARM64_CPU
        return true;
#else
        return false;
#endif
    }
    bool feature_IWMMXT_supported() {
#if ARM_CPU
        requires_arm(AT_HWCAP);
        return eax() & HWCAP_IWMMXT;
#elif ARM64_CPU
        return true; // TODO: is it correct that all AArch64 processors have IWMMXT?
#else
        return false;
#endif
    }
    bool feature_NEON_supported() {
#if ARM_CPU
        requires_arm(AT_HWCAP);
        return eax() & HWCAP_NEON;
#elif ARM64_CPU
        return true;
#else
        return false;
#endif
    }
    bool feature_XSAVE_supported_by_processor() {
        requires_x86(1);
        return ecx(26);
    }
    bool feature_XSAVE_supported_by_OS() {
        if (!feature_XSAVE_supported_by_processor())
            return false;

        requires_x86(1);
        return ecx(27);
    }
    bool feature_AVX_supported_by_processor() {
        requires_x86(1);
        return ecx(28);
    }
    bool feature_AVX_supported_by_OS() {
        if (!feature_AVX_supported_by_processor() || !feature_XSAVE_supported_by_OS())
            return false;

        return (xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x6) == 0x6;
    }
    bool feature_F16C_supported() {
        requires_x86(1);
        return ecx(29);
    }
    bool feature_RDRAND_supported() {
        requires_x86(1);
        return ecx(30);
    }

    bool feature_FPU_on_chip() {
        requires_x86(1);
        return edx(0);
    }
    bool feature_VME_supported() {
        requires_x86(1);
        return edx(1);
    }
    bool feature_DE_supported() {
        requires_x86(1);
        return edx(2);
    }
    bool feature_PSE_supported() {
        requires_x86(1);
        return edx(3);
    }
    bool feature_TSC_supported() {
        requires_x86(1);
        return edx(4);
    }
    bool feature_MSR_supported() {
        requires_x86(1);
        return edx(5);
    }
    bool feature_PAE_supported() {
        requires_x86(1);
        return edx(6);
    }
    bool feature_MCE_supported() {
        requires_x86(1);
        return edx(7);
    }
    bool feature_CMPXCHG8B_supported() {
        requires_x86(1);
        return edx(8);
    }
    bool feature_APIC_supported() {
        requires_x86(1);
        return edx(9);
    }
    bool feature_SEP_supported() {
        requires_x86(1);
        return edx(11);
    }
    bool feature_MTRR_supported() {
        requires_x86(1);
        return edx(12);
    }
    bool feature_PGE_supported() {
        requires_x86(1);
        return edx(13);
    }
    bool feature_MCA_supported() {
        requires_x86(1);
        return edx(14);
    }
    bool feature_CMOV_supported() {
        requires_x86(1);
        return edx(15);
    }
    bool feature_PAT_supported() {
        requires_x86(1);
        return edx(16);
    }
    bool feature_PSE_36_supported() {
        requires_x86(1);
        return edx(17);
    }
    bool feature_PSN_supported() {
        requires_x86(1);
        return edx(18);
    }
    bool feature_CLFLUSH_supported() {
        requires_x86(1);
        return edx(19);
    }
    bool feature_debug_store_supported() {
        requires_x86(1);
        return edx(21);
    }
    bool feature_ACPI_supported() {
        requires_x86(1);
        return edx(22);
    }
    bool feature_MMX_supported() {
        requires_x86(1);
        return edx(23);
    }
    bool feature_FXSR_supported() {
        requires_x86(1);
        return edx(24);
    }
    bool feature_SSE_supported_by_processor() {
        requires_x86(1);
        return edx(25);
    }
    bool feature_SSE_supported_by_OS() {
        if (!feature_SSE_supported_by_processor() || !feature_XSAVE_supported_by_OS())
            return false;

        return xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x2;
    }
    bool feature_SSE2_supported_by_processor() {
        requires_x86(1);
        return edx(26);
    }
    bool feature_SSE2_supported_by_OS() {
        if (!feature_SSE2_supported_by_processor() || !feature_XSAVE_supported_by_OS())
            return false;

        return xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x2;
    }
    bool feature_self_snoop_supported() {
        requires_x86(1);
        return edx(27);
    }
    bool feature_HTT_supported() {
        requires_x86(1);
        return edx(28);
    }
    bool feature_TM_supported() {
        requires_x86(1);
        return edx(29);
    }
    bool feature_PBE_supported() {
        requires_x86(1);
        return edx(31);
    }

    // TODO: leaf 02H

    uint64_t processor_serial_number_lo_bits() {
        if (!feature_PSN_supported())
            return 0;

        requires_x86(3);

        return (uint64_t(edx()) << 32) | ecx();
    }

    // TODO: leaf 04H

    uint16_t monitor_line_size_minimum() {
        requires_x86(5);
        return eax(0, 16);
    }
    uint16_t monitor_line_size_maximum() {
        requires_x86(5);
        return ebx(0, 16);
    }

    bool monitor_mwait_extension_enumeration_supported() {
        requires_x86(5);
        return ecx(0);
    }
    bool monitor_mwait_interrupts_break_even_when_disabled() {
        requires_x86(5);
        return ecx(1);
    }

    uint8_t mwait_sub_C_states_supported(uint8_t _class) {
        requires_x86(5);
        if (_class > 7)
            return 0;
        return edx(4 * _class, 4);
    }

    bool thermal_digital_sensor_supported() {
        requires_x86(6);
        return eax(0);
    }
    bool thermal_Intel_TurboBoost_supported() {
        requires_x86(6);
        return eax(1);
    }
    bool thermal_APIC_timer_always_running_supported() {
        requires_x86(6);
        return eax(2);
    }
    bool thermal_PLN_controls_supported() { // Power limit notification controls
        requires_x86(6);
        return eax(4);
    }
    bool thermal_ECMD_supported() { // Clock modulation duty cycle extension
        requires_x86(6);
        return eax(5);
    }
    bool thermal_PTM_supported() { // Package thermal management
        requires_x86(6);
        return eax(6);
    }
    bool thermal_HWP_supported() { // HWP base registers
        requires_x86(6);
        return eax(7);
    }
    bool thermal_HWP_notification_supported() {
        requires_x86(6);
        return eax(8);
    }
    bool thermal_HWP_Activity_Window_supported() {
        requires_x86(6);
        return eax(9);
    }
    bool thermal_HWP_Energy_Performance_Preference_supported() {
        requires_x86(6);
        return eax(10);
    }
    bool thermal_HWP_Package_Level_Request_supported() {
        requires_x86(6);
        return eax(11);
    }
    bool thermal_HDC_supported() { // HDC base registers
        requires_x86(6);
        return eax(13);
    }
    bool thermal_Intel_Turbo_Boost_3_supported() {
        requires_x86(6);
        return eax(14);
    }
    bool thermal_Highest_Performance_change_supported() {
        requires_x86(6);
        return eax(15);
    }
    bool thermal_HWP_PECI_override_supported() {
        requires_x86(6);
        return eax(16);
    }
    bool thermal_flexible_HWP_supported() {
        requires_x86(6);
        return eax(17);
    }
    bool thermal_HWP_request_fast_access_supported() {
        requires_x86(6);
        return eax(18);
    }
    bool thermal_ignoring_idle_logical_processor_supported() {
        requires_x86(6);
        return eax(20);
    }

    uint8_t thermal_sensor_interrupt_thresholds() {
        requires_x86(6);
        return ebx(0, 4);
    }

    bool thermal_hardware_coordination_feedback_supported() {
        requires_x86(6);
        return ecx(0);
    }
    bool thermal_performance_energy_bias_preference() {
        requires_x86(6);
        return ecx(3);
    }

    uint32_t maximum_07H_subleaf() {
        requires_x86(7);
        return eax();
    }

    bool feature_FSGSBASE_supported() {
        requires_x86(7);
        return ebx(0);
    }
    bool feature_tsc_adjust_msr_supported() {
        requires_x86(7);
        return ebx(1);
    }
    bool feature_Software_Guard_Extensions_supported() {
        requires_x86(7);
        return ebx(2);
    }
    bool feature_BMI1_supported() {
        requires_x86(7);
        return ebx(3);
    }
    bool feature_HLE_supported() {
        requires_x86(7);
        return ebx(4);
    }
    bool feature_AVX2_supported_by_processor() {
        requires_x86(7);
        return ebx(5);
    }
    bool feature_AVX2_supported_by_OS() {
        if (!feature_AVX2_supported_by_processor() || !feature_XSAVE_supported_by_OS())
            return false;

        return (xgetbv(_XCR_XFEATURE_ENABLED_MASK) & 0x6) == 0x6;
    }
    bool feature_FPU_data_pointer_updated_on_exceptions() {
        requires_x86(7);
        return ebx(6);
    }
    bool feature_SMEP_supported() {
        requires_x86(7);
        return ebx(7);
    }
    bool feature_BMI2_supported() {
        requires_x86(7);
        return ebx(8);
    }
    bool feature_enhanced_REP_MOVSB_supported() {
        requires_x86(7);
        return ebx(9);
    }
    bool feature_INVPCID_supported() {
        requires_x86(7);
        return ebx(10);
    }
    bool feature_RTM_supported() {
        requires_x86(7);
        return ebx(11);
    }
    bool feature_RDT_M_supported() {
        requires_x86(7);
        return ebx(12);
    }
    bool feature_deprecated_FPU_CS_and_DS() {
        requires_x86(7);
        return ebx(13);
    }
    bool feature_MPX_supported() {
        requires_x86(7);
        return ebx(14);
    }
    bool feature_RDT_A_supported() {
        requires_x86(7);
        return ebx(15);
    }
    bool feature_AVX512F_supported() {
        requires_x86(7);
        return ebx(16);
    }
    bool feature_AVX512DQ_supported() {
        requires_x86(7);
        return ebx(17);
    }
    bool feature_RDSEED_supported() {
        requires_x86(7);
        return ebx(18);
    }
    bool feature_ADX_supported() {
        requires_x86(7);
        return ebx(19);
    }
    bool feature_SMAP_supported() {
        requires_x86(7);
        return ebx(20);
    }
    bool feature_AVX512_IFMA_supported() {
        requires_x86(7);
        return ebx(21);
    }
    bool feature_CLFLUSHOPT_supported() {
        requires_x86(7);
        return ebx(23);
    }
    bool feature_CLWB_supported() {
        requires_x86(7);
        return ebx(24);
    }
    bool feature_Intel_Processor_Trace_supported() {
        requires_x86(7);
        return ebx(25);
    }
    bool feature_AVX512PF_supported() {
        requires_x86(7);
        return ebx(26);
    }
    bool feature_AVX512ER_supported() {
        requires_x86(7);
        return ebx(27);
    }
    bool feature_AVX512CD_supported() {
        requires_x86(7);
        return ebx(28);
    }
    bool feature_SHA1_supported() {
#if ARM_CPU
        requires_arm(AT_HWCAP2);
        return eax() & HWCAP2_SHA1;
#elif ARM64_CPU
        requires_arm(AT_HWCAP);
        return eax() & HWCAP_SHA1;
#else
        requires_x86(7);
        return ebx(29);
#endif
    }
    bool feature_SHA2_supported() {
#if ARM_CPU
        requires_arm(AT_HWCAP2);
        return eax() & HWCAP2_SHA2;
#elif ARM64_CPU
        requires_arm(AT_HWCAP);
        return eax() & HWCAP_SHA2;
#else
        return feature_SHA1_supported();
#endif
    }
    bool feature_AVX512BW_supported() {
        requires_x86(7);
        return ebx(30);
    }
    bool feature_AVX512VL_supported() {
        requires_x86(7);
        return ebx(31);
    }

    bool feature_PREFETCHWT1_supported() {
        requires_x86(7);
        return ecx(0);
    }
    bool feature_AVX512_VBMI_supported() {
        requires_x86(7);
        return ecx(1);
    }
    bool feature_UMIP_supported() {
        requires_x86(7);
        return ecx(2);
    }
    bool feature_PKU_supported_by_processor() {
        requires_x86(7);
        return ecx(3);
    }
    bool feature_PKU_supported_by_OS() {
        requires_x86(7);
        return ecx(4);
    }
    bool feature_AVX512_VPOPCNTDQ_supported() {
        requires_x86(7);
        return ecx(14);
    }
    uint8_t feature_MAWAU() {
        requires_x86(7);
        return ecx(17, 5);
    }
    bool feature_RDPID_and_TSC_AUX_supported() {
        requires_x86(7);
        return ecx(22);
    }
    bool feature_SGX_Launch_Configuration_supported() {
        requires_x86(7);
        return ecx(30);
    }

    bool feature_AVX512_4VNNIW_supported() {
        requires_x86(7);
        return edx(2);
    }
    bool feature_AVX512_4FMAPS_supported() {
        requires_x86(7);
        return edx(3);
    }
    bool feature_IBRS_and_IBPB_supported() {
        requires_x86(7);
        return edx(26);
    }
    bool feature_STIBP_supported() {
        requires_x86(7);
        return edx(27);
    }
    bool feature_L1D_FLUSH_supported() {
        requires_x86(7);
        return edx(28);
    }
    bool feature_arch_capabilities_MSR_supported() {
        requires_x86(7);
        return edx(29);
    }
    bool feature_SSBD_supported() {
        requires_x86(7);
        return edx(31);
    }

    // TODO: 09H

    uint8_t arch_performance_version_ID() {
        requires_x86(0xA);
        return eax(0, 8);
    }
    uint8_t arch_performance_counter_per_logical_processor() {
        requires_x86(0xA);
        return eax(8, 8);
    }
    uint8_t arch_performance_counter_bit_width() {
        requires_x86(0xA);
        return eax(16, 8);
    }
    uint8_t arch_performance_EBX_bit_vector_length() {
        requires_x86(0xA);
        return eax(24, 8);
    }

    bool arch_performance_core_cycle_event_available() {
        requires_x86(0xA);
        return ebx(0);
    }
    bool arch_performance_instruction_retired_event_available() {
        requires_x86(0xA);
        return ebx(1);
    }
    bool arch_performance_reference_cycles_event_available() {
        requires_x86(0xA);
        return ebx(2);
    }
    bool arch_performance_last_level_cache_reference_event_available() {
        requires_x86(0xA);
        return ebx(3);
    }
    bool arch_performance_last_level_cache_misses_event_available() {
        requires_x86(0xA);
        return ebx(4);
    }
    bool arch_performance_branch_instruction_retired_event_available() {
        requires_x86(0xA);
        return ebx(5);
    }
    bool arch_performance_branch_mispredict_retired_event_available() {
        requires_x86(0xA);
        return ebx(6);
    }

    uint8_t arch_performance_fixed_function_performance_counters() {
        if (arch_performance_version_ID() <= 1)
            return 0;

        requires_x86(0xA);

        return edx(0, 5);
    }
    uint8_t arch_performance_fixed_function_performance_counter_bit_width() {
        if (arch_performance_version_ID() <= 1)
            return 0;

        requires_x86(0xA);

        return edx(5, 8);
    }
    bool arch_performance_AnyThread_deprecated() {
        requires_x86(0xA);
        return edx(15);
    }

    // TODO: 0BH

    uint64_t XCR0_supported_bits() {
        requires_x86(0xD);
        return (uint64_t(edx()) << 32) | eax();
    }
    uint32_t XSAVE_XRSTOR_maximum_size_of_all_enabled_features() {
        requires_x86(0xD);
        return ebx();
    }
    uint32_t XSAVE_XRSTOR_maximum_size_of_all_supported_features() {
        requires_x86(0xD);
        return ecx();
    }

    bool feature_XSAVEOPT_supported() {
        requires_x86(0xD, 1);
        return eax(0);
    }
    bool feature_XSAVEC_and_compacted_XRSTOR_supported() {
        requires_x86(0xD, 1);
        return eax(1);
    }
    bool feature_XGETBV_1_supported() {
        requires_x86(0xD, 1);
        return eax(2);
    }
    bool feature_XSAVES_and_XRSTORS_supported() {
        requires_x86(0xD, 1);
        return eax(3);
    }

    uint32_t size_of_XCR0_XSS_enabled_states() {
        requires_x86(0xD, 1);
        return ebx();
    }

    uint64_t XSS_MSR_supported_bits() {
        requires_x86(0xD, 1);
        return (uint64_t(edx()) << 32) | ecx();
    }

    // TODO: 0FH
    // TODO: 10H
    // TODO: 12H
    // TODO: 14H
    // TODO: 15H

    uint16_t processor_base_frequency_MHz() {
        requires_x86(0x16);
        return eax(0, 16);
    }
    uint16_t processor_max_frequency_MHz() {
        requires_x86(0x16);
        return ebx(0, 16);
    }
    uint16_t processor_bus_reference_frequency_MHz() {
        requires_x86(0x16);
        return ecx(0, 16);
    }

    uint32_t max_SOCID_index() {
        requires_x86(0x17);
        return eax();
    }
    uint16_t SOC_vendor_ID() {
        requires_x86(0x17);
        return ebx(0, 16);
    }
    bool SOC_vendor_ID_is_standard() {
        requires_x86(0x17);
        return ebx(16);
    }
    bool SOC_vendor_ID_is_assigned_by_Intel() {return !SOC_vendor_ID_is_standard();}

    uint32_t SOC_project_ID() {
        requires_x86(0x17);
        return ecx();
    }
    uint32_t SOC_stepping_ID() {
        requires_x86(0x17);
        return edx();
    }

    std::string SOC_brand_string_UTF8() {
        char brand_string[64] = {0};

        for (uint32_t i = 0; i < 3; ++i)
        {
            requires_x86(0x17, 1 + i);
            if (!valid())
                return std::string();

            *reinterpret_cast<uint32_t *>(brand_string + i * 16) = eax();
            *reinterpret_cast<uint32_t *>(brand_string + i * 16 + 4) = ebx();
            *reinterpret_cast<uint32_t *>(brand_string + i * 16 + 8) = ecx();
            *reinterpret_cast<uint32_t *>(brand_string + i * 16 + 12) = edx();
        }

        return brand_string;
    }

    // TODO: 18H
    // TODO: 1FH

    bool feature_64_bit_LAHF_SAHF_supported() {
        requires_x86(0x80000001);
        return ecx(0);
    }
    bool feature_SVM_supported() {
        requires_x86(0x80000001);
        return ecx(2);
    }
    bool feature_LZCNT_supported() {
        requires_x86(0x80000001);
        return ecx(5);
    }
    bool feature_SSE4A_supported() {
        requires_x86(0x80000001);
        return ecx(6);
    }
    bool feature_PREFETCHW_supported() {
        requires_x86(0x80000001);
        return ecx(8);
    }
    bool feature_3DNow_PREFETCH_supported() {return feature_PREFETCHW_supported();}
    bool feature_XOP_supported() {
        requires_x86(0x80000001);
        return ecx(11);
    }
    bool feature_SKINIT_supported() {
        requires_x86(0x80000001);
        return ecx(12);
    }
    bool feature_FMA4_supported() {
        requires_x86(0x80000001);
        return ecx(16);
    }
    bool feature_TBM_supported() {
        requires_x86(0x80000001);
        return ecx(21);
    }
    bool feature_MONITORX_supported() {
        requires_x86(0x80000001);
        return ecx(29);
    }
    bool feature_64_bit_SYSCALL_SYSRET_supported() {
        requires_x86(0x80000001);
        return edx(11);
    }
    bool feature_execute_disable_supported() {
        requires_x86(0x80000001);
        return edx(20);
    }
    bool feature_MMX_extensions_supported() {
        requires_x86(0x80000001);
        return edx(22);
    }
    bool feature_1GB_pages_supported() {
        requires_x86(0x80000001);
        return edx(26);
    }
    bool feature_RDTSCP_supported() {
        requires_x86(0x80000001);
        return edx(27);
    }
    bool feature_64_bit_mode_supported() {
        requires_x86(0x80000001);
        return edx(29);
    }
    bool feature_3DNow_extensions_supported() {
        requires_x86(0x80000001);
        return edx(30);
    }
    bool feature_3DNow_supported() {
        requires_x86(0x80000001);
        return edx(31);
    }

    std::string processor_brand_string() {
        char brand_string[64] = {0};

        for (uint32_t i = 0; i < 3; ++i)
        {
            requires_x86(0x80000002 + i);
            if (!valid())
                return std::string();

            *reinterpret_cast<uint32_t *>(brand_string + i * 16) = eax();
            *reinterpret_cast<uint32_t *>(brand_string + i * 16 + 4) = ebx();
            *reinterpret_cast<uint32_t *>(brand_string + i * 16 + 8) = ecx();
            *reinterpret_cast<uint32_t *>(brand_string + i * 16 + 12) = edx();
        }

        return brand_string;
    }

    uint8_t cache_line_size() {
        requires_x86(0x80000006);
        return ecx(0, 8);
    }
    uint32_t cache_size() {
        requires_x86(0x80000006);
        return ecx(16, 16) * 1024;
    }

    bool feature_invariant_TSC_supported() {
        requires_x86(0x80000007);
        return edx(8);
    }

    uint8_t physical_address_bits() {
        requires_x86(0x80000008);
        return eax(0, 8);
    }
    uint8_t linear_address_bits() {
        requires_x86(0x80000008);
        return eax(8, 8);
    }

    bool vendor_is_Intel() {return vendor() == "GenuineIntel";}
    bool vendor_is_AMD() {return vendor() == "AuthenticAMD" || vendor() == "AMDisbetter!";}
    bool vendor_is_Centaur() {return vendor() == "CentaurHauls";}
    bool vendor_is_Cyrix() {return vendor() == "CyrixInstead";}
    bool vendor_is_Hygon() {return vendor() == "HygonGenuine";}
    bool vendor_is_Transmeta() {return vendor() == "TransmetaCPU" || vendor() == "GenuineTMx86";}
    bool vendor_is_NationalSemiconductor() {return vendor() == "Geode by NSC";}
    bool vendor_is_NexGen() {return vendor() == "NexGenDriven";}
    bool vendor_is_Rise() {return vendor() == "RiseRiseRise";}
    bool vendor_is_SiS() {return vendor() == "SiS SiS SiS ";}
    bool vendor_is_UMC() {return vendor() == "UMC UMC UMC ";}
    bool vendor_is_VIA() {return vendor() == "VIA VIA VIA ";}
    bool vendor_is_Vortex() {return vendor() == "Vortex86 SoC";}

    bool vendor_is_bhyve() {return vendor() == "bhyve bhyve ";}
    bool vendor_is_KVM() {return vendor() == "KVMKVMKVM";}
    bool vendor_is_MS_HyperV_or_Windows_Virtual_PC() {return vendor() == "Microsoft Hv";}
    bool vendor_is_Parallels() {return vendor() == " lrpepyh vr";} // sic, note that this is not a cat on the keyboard!
    bool vendor_is_VMware() {return vendor() == "VMwareVMware";}
    bool vendor_is_Xen_HVM() {return vendor() == "XenVMMXenVMM";}

    bool valid() const {return m_valid;}
};

#endif // GENERIC_CPUID_H
