#pragma once
#include "Utility.h"
#include <iostream>
#include <string>

class SectionDataStrtab {
	std::string section_data = "";
public:
	SectionDataStrtab() = default;
	std::string get_name(uint32_t offset) const;
	SectionDataStrtab(std::string section_data, FieldOfHeaderSectionTable header_data);
};