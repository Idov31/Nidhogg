#pragma once
#include "pch.h"

template<typename T>
concept TString = std::same_as<T, std::string> || std::same_as<T, std::wstring>;

template<typename T>
using IsUnicodeString = std::is_same_v<typename T::value_type, std::wstring>;

class ConvertorException : public std::runtime_error
{
	std::string msg;
public:
	ConvertorException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override
	{
		return msg.c_str();
	}
};

/*
* Description:
* ConvertToVector is responsible for converting a raw patch string into a vector of bytes.
*
* Parameters:
* @rawPatch [_In_ std::wstring] -- The raw patch string to be converted.
*
* Returns:
* @vec		[std::vector<byte>] -- The vector of bytes representing the patch.
*/
template<TString String>
inline std::vector<byte> ConvertToVector(_In_ String rawPatch) {
	int b;
	std::vector<byte> vec;

	if constexpr (std::same_as<String, std::wstring>) {
		std::wstringstream rawPatchStream(rawPatch);
		std::wstringstream byteToAdd;

		for (wchar_t i; rawPatchStream >> i; rawPatchStream.good()) {
			byteToAdd << std::hex << i;

			if (rawPatchStream.peek() == L',') {
				rawPatchStream.ignore();
				byteToAdd >> b;
				vec.push_back(b);
				byteToAdd.clear();
			}
		}
		byteToAdd >> b;
	}
	else {
		std::stringstream rawPatchStream(rawPatch);
		std::stringstream byteToAdd;

		for (char i; rawPatchStream >> i; rawPatchStream.good()) {
			byteToAdd << std::hex << i;

			if (rawPatchStream.peek() == L',') {
				rawPatchStream.ignore();
				byteToAdd >> b;
				vec.push_back(b);
				byteToAdd.clear();
			}
		}
		byteToAdd >> b;
	}
	vec.push_back(b);

	return vec;
}

/*
* Description:
* ConvertToInt is responsible for converting a raw string into an integer.
*
* Parameters:
* @rawString [_In_ String] -- The raw string to be converted.
*
* Returns:
* @int					   -- The integer value of the raw string.
*/
template<TString String, typename N>
inline N ConvertToNumber(_In_ String rawString) {
	String str = rawString;
	bool isHex = false;

	if (str.starts_with(String("0x")) || str.starts_with(String("0X"))) {
		str.erase(0, 2);
		isHex = true;
	}
	if (str.empty() || !std::all_of(str.begin(), str.end(), ::isdigit))
		throw ConvertorException("Invalid integer string");
	return isHex ? static_cast<N>(std::stoi(str, nullptr, 16)) : static_cast<N>(std::stoi(str));
}