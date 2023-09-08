// Axel '0vercl0k' Souchet - January 12 2022
#include "options.hpp"
#include "platform.h"
#include "program.hpp"
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <exception>
#include <unordered_map>

#include "windbgext.hpp"

#define EXT_MAJOR_VER  1
#define EXT_MINOR_VER  0

#define NUM_V "2.1"
#ifdef ARCH_X64
#define VERSION_TMP NUM_V " x64 built the " __DATE__ " " __TIME__
#elif defined ARCH_X86
#define VERSION_TMP NUM_V " x86 built the " __DATE__ " " __TIME__
#else
#define VERSION_TMP NUM_V " arm64 built the " __DATE__ " " __TIME__
#endif

#define VERSION_TM VERSION_TMP " for " SYSTEM_PLATFORM

#ifdef _DEBUG
#define VERSION VERSION_TM " (Debug)"
#else
#define VERSION VERSION_TM " (Release)"
#endif

Options_t g_opts;

struct compare
{
    std::string key;
    compare(std::string const &i): key(i) {}

    bool operator()(std::string const &i) {
        return (i == key);
    }
};

bool does_contain(std::vector<std::string> args, std::string arg) {
    return (std::any_of(args.begin(), args.end(), compare(arg))) ? true : false;
}

std::string return_arg_value(std::vector<std::string> args, std::string arg) {
    std::vector<std::string>::iterator it = std::find(args.begin(), args.end(), arg);
    return (it != args.end()) ? args[(std::distance(args.begin(), it) + 1)] : std::string("");
}

uint32_t return_arg_value_as_int(std::vector<std::string> args, std::string arg) {
    std::vector<std::string>::iterator it = std::find(args.begin(), args.end(), arg);
    uint32_t value = 0;

    if(it != args.end()) {
        std::stringstream(args[(std::distance(args.begin(), it) + 1)]) >> value;
    }

    return value;
}

CPU::E_CPU get_cpu(uint8_t value) {
  switch (value)
  {
  case 0:
    return CPU::CPU_x86;
  case 1:
    return CPU::CPU_x64;
  case 2:
    return CPU::CPU_ARM;
  case 3:
    return CPU::CPU_ARM64;
  default:
    return CPU::CPU_UNKNOWN;
  }
}

Options_t build_args_from_string(const std::string &args){
    Options_t rp_args;
    std::stringstream ss(args);
    std::string param;
    std::vector<std::string> list_args;


    while (ss >> param) {
        list_args.push_back(param);
    }

    // --file
    rp_args.file = does_contain(list_args, "-f") ? return_arg_value(list_args, "-f") : "";

    // --help
    rp_args.help = does_contain(list_args, "-h") ? true : false;

    // --info
    // Remove for now, maybe will work on the port when I get time.
    //rp_args.display = does_contain(list_args, "-i") ? true : false;

    // --rop
    rp_args.rop = does_contain(list_args, "-r") ? return_arg_value_as_int(list_args, "-r") : 0;

    // --raw
    rp_args.raw = does_contain(list_args, "--raw") ? get_cpu(return_arg_value_as_int(list_args, "--raw")) : CPU::CPU_UNKNOWN;

    // --unique
    rp_args.unique = does_contain(list_args, "--unique") ? true : false;

    // --search_hex
    rp_args.shexa = does_contain(list_args, "--search-hexa") ? return_arg_value(list_args, "--search-hexa") : "";

    // --max_thread
    rp_args.maxth = does_contain(list_args, "--max-thread") ? return_arg_value_as_int(list_args, "--max-thread") : 2;

    // --bad_bytes
    rp_args.badbytes = does_contain(list_args, "--bad-bytes") ? return_arg_value(list_args, "--bad-bytes") : "";

    // --search_int
    rp_args.sint = does_contain(list_args, "--search-int") ? return_arg_value(list_args, "--search-int") : "";

    // --version
    rp_args.version = does_contain(list_args, "-v") ? true : false;

    // --thumb
    rp_args.thumb = does_contain(list_args, "--thumb") ? true : false;

    // --va
    rp_args.va = does_contain(list_args, "--va") ? return_arg_value(list_args, "--va") : "";

    // --allow-branches
    rp_args.allow_branches = does_contain(list_args, "--allow-branches") ? true : false;

    // --print-bytes
    rp_args.print_bytes = does_contain(list_args, "--print-bytes") ? true : false;

    return rp_args;
}

extern "C" __declspec(dllexport) HRESULT CALLBACK
rp(IDebugClient* pDebugClient, PCSTR args) {
  WinDBGExt windbgExt(pDebugClient);

  windbgExt.PrintOut("rp++: a fast ROP gadget finder for pe/elf/mach-o x86/x64/ARM/ARM64 "
                     "binaries\nby Axel '0vercl0k' Souchet.\nPorted as a WinDBG Extension by Taha Draidia @tahadraidia.\n");
  if(args){
    g_opts = build_args_from_string(std::string(args));
  }else{
    windbgExt.PrintOut("No parameters were passed to rp++.\n");
    return E_ABORT;
  }

  try {
    if (g_opts.version) {
     windbgExt.PrintOut("You are currently using the version %s of rp++.\n", VERSION);
    }

    if(g_opts.help) {
     windbgExt.PrintOut("%s\n", R"(
      Usage: !rp [OPTIONS]
  Options:
    -h,--help                   Print this help message and exit
    -f, TEXT REQUIRED     Binary path
    -r, UINT               find useful gadget for your future exploits, arg is the gadget maximum size in instructions
    --raw ENUM:value in {x86->0,x64->1,arm->2,arm64->3} OR {0,1,2,3}
                                find gadgets in a raw file
    --unique                    display only unique gadget
    --search-hexa TEXT          try to find hex values
    --max-thread UINT           set the maximum number of threads that can be used
    --bad-bytes TEXT            the bytes you don't want to see in the gadgets' addresses
    --search-int TEXT           try to find a pointer on a specific integer value
    -v,--version                print version information
    --thumb                     enable thumb mode when looking for ARM gadgets
    --va TEXT                   don't use the image base of the binary, but yours instead
    --allow-branches            allow branches in a gadget
    --print-bytes               print the gadget bytes
    )");
        }

    std::string file_image{"foobar.exe"};

    if(g_opts.file.empty()){
      char imageName[MAX_PATH] = { 0 };
      DWORD imageSize = sizeof(imageName);

      if(!QueryFullProcessImageNameA(windbgExt.GetDebuggeeHandle(), 0 /* win32 path */, imageName, &imageSize)){
        windbgExt.PrintOut("QueryFullProcessImageNameA() failed (%ld)\n", GetLastError());
        return E_ABORT;
      }

      file_image.assign(imageName);
    }else{
      file_image.assign(g_opts.file);
    }

    Program p(file_image, g_opts.raw);

    if (g_opts.display >= VERBOSE_LEVEL_1 &&
        g_opts.display <= VERBOSE_LEVEL_3) {
      p.display_information_wd(windbgExt, VerbosityLevel(g_opts.display));
    }

    // Here we set the base being 0 if we want to have absolute virtual
    // memory address displayed
    const uint64_t base = g_opts.va.size() > 0
                              ? std::strtoull(g_opts.va.c_str(), nullptr, 0)
                              : p.get_image_base_address();
    if (g_opts.rop > 0) {
      const uint32_t options = g_opts.thumb ? 1 : 0;
      windbgExt.PrintOut("\nWait a few seconds, rp++ is looking for gadgets (%ld "
                 "threads max)..\n",
                 g_opts.maxth);

      GadgetMultiset all_gadgets =
          p.find_gadgets(g_opts.rop, options, g_opts.maxth, base);

      windbgExt.PrintOut("A total of %ld gadgets found.\n", all_gadgets.size());
      std::vector<uint8_t> badbyte_list;
      if (g_opts.badbytes.size() > 0) {
        badbyte_list = string_to_hex(g_opts.badbytes);
      }

      uint64_t nb_gadgets_filtered = 0;
      if (g_opts.unique) {
        auto unique_gadgets = only_unique_gadgets(all_gadgets);

        windbgExt.PrintOut("You decided to keep only the unique ones, %ld unique "
                   "gadgets found.\n",
                   unique_gadgets.size());

        // Now we walk the gadgets found and set the VA
        for (const auto &unique_gadget : unique_gadgets) {
          display_gadget_lf_wd(windbgExt, unique_gadget.get_first_absolute_address(),
                            unique_gadget);
        }
      } else {
        for (const auto &gadget : all_gadgets) {
          display_gadget_lf_wd(windbgExt, gadget.get_first_absolute_address(), gadget);
        }
      }

      if (g_opts.badbytes.size() > 0) {
        windbgExt.PrintOut(
            "\n%ld gadgets have been filtered because of your bad-bytes.\n",
            nb_gadgets_filtered);
      }
    }

    if (g_opts.shexa.size() > 0) {
      const std::vector<uint8_t> &hex_values = string_to_hex(g_opts.shexa);
      p.search_and_display_wd(windbgExt, hex_values.data(), hex_values.size(), base);
    }

    if (g_opts.sint.size() > 0) {
      const uint32_t val = std::strtoul(g_opts.sint.c_str(), nullptr, 16);
      p.search_and_display_wd(windbgExt, (const uint8_t *)&val, sizeof(val), base);
    }
  } catch (const std::exception &e) {
    windbgExt.PrintOut("%s\n", e.what());
  }

  return S_OK;
}

extern "C" __declspec(dllexport) HRESULT CALLBACK
DebugExtensionInitialize(PULONG Version, PULONG Flags) {
  *Version = DEBUG_EXTENSION_VERSION(EXT_MAJOR_VER, EXT_MINOR_VER);
  *Flags = 0;
  return S_OK;
}
