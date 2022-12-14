#include "sectionTable.h"

std::string SectionDataStrtab::get_name(uint32_t offset) const {
    if (offset >= section_data.size())
        return "";
    std::string res = "";
    while (section_data[offset] != '\0')
        res += section_data[offset++];
      
    return res;
}

SectionDataStrtab::SectionDataStrtab(std::string section_data, FieldOfHeaderSectionTable header_data) : section_data(section_data) {}