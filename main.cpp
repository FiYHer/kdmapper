#include "kdmapper.hpp"

/*
驱动加载器
kdmapper 1809,1903,1909
*/

int main(const int argc, char** argv)
{
	std::cout << "kdmapper x64 - 1809 1903 1909" << std::endl;

	//用法   kdmapper hack.sys
	if (argc != 2 || std::filesystem::path(argv[1]).extension().string().compare(".sys"))
	{
		std::cout << "[-] 错误的用法" << std::endl;
		std::cout << "-> 要这样子用\t" << argv[0] << " 要加载的驱动" << std::endl;
		return -1;
	}

	//判断漏洞驱动是否占用
	if (intel_driver::IsRunning())
	{
		std::cout << "[-] 漏洞驱动被占用" << std::endl;
		return -1;
	}

	//判断准备加载的黑客驱动是否存在
	const std::string driver_path = argv[1];
	if (!std::filesystem::exists(driver_path))
	{
		std::cout << "[-] 驱动文件 " << driver_path << " 不存在" << std::endl;
		return -1;
	}

	//获取漏洞驱动的连接
	HANDLE iqvw64e_device_handle = intel_driver::Load();
	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-] 无法加载漏洞驱动 iqvw64e.sys" << std::endl;
		return -1;
	}

	//利用漏洞驱动映射黑客驱动
	if (!kdmapper::MapDriver(iqvw64e_device_handle, driver_path))
	{
		std::cout << "[-] 无法映射黑客驱动 " << driver_path << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}

	//卸载漏洞驱动
	intel_driver::Unload(iqvw64e_device_handle);

	std::cout << "[+] 驱动加载成功" << std::endl;
}