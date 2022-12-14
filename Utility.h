#pragma once
#include "elfFileReader.h"

#include <iostream>
#include <algorithm>
#include <map>
#include <string>
#include <vector>

class StHelpers {
private:
    static std::string abstract_getter(int index, const std::map<int, std::string> &gen) {
        typename std::map<int, std::string>::const_iterator it = gen.find(index);
        if (it == gen.end())
            return  "UNKNOWN";
        else
            return it->second;
    }
    static std::map<int, std::string> types;
    static std::map<int, std::string> indexes;
    static std::map<int, std::string> visibilities;
    static std::map<int, std::string> binds;

public:

    static std::string get_type(int index) {
        return abstract_getter(index, types);
    }
    static std::string get_index(int index) {
        std::string ind = abstract_getter(index, indexes);
        return (ind != "UNKNOWN") ? ind : std::to_string(index);
    }
    static std::string get_visibility(int index) {
        return abstract_getter(index, visibilities);
    }
    static std::string get_bind(int index) {
        return abstract_getter(index, binds);
    }
};

struct FieldOfHeaderSectionTable {
    uint32_t sh_name = 0;
    uint32_t sh_type = 0;
    uint32_t sh_flags = 0;
    uint32_t sh_addr = 0;
    uint32_t sh_offset = 0;
    uint32_t sh_size = 0;
    uint32_t sh_link = 0;
    uint32_t sh_info = 0;
    uint32_t sh_addralign = 0;
    uint32_t sh_entsize = 0;

    FieldOfHeaderSectionTable() = default;
    FieldOfHeaderSectionTable(ElfFileReader& elf_data) {
        sh_name = elf_data.get_next_n_bytes(4);
        sh_type = elf_data.get_next_n_bytes(4);
        sh_flags = elf_data.get_next_n_bytes(4);
        sh_addr = elf_data.get_next_n_bytes(4);
        sh_offset = elf_data.get_next_n_bytes(4);
        sh_size = elf_data.get_next_n_bytes(4);
        sh_link = elf_data.get_next_n_bytes(4);
        sh_info = elf_data.get_next_n_bytes(4);
        sh_addralign = elf_data.get_next_n_bytes(4);
        sh_entsize = elf_data.get_next_n_bytes(4);
    };
};

struct SymbOfSymbolTable {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint8_t st_type;
    uint8_t st_bind;
    std::string st_type_txt;
    std::string st_vis_txt;
    std::string st_bind_txt;
    std::string st_index_txt;
    std::string name = "";

    SymbOfSymbolTable() = default;
    SymbOfSymbolTable(ElfFileReader& elf_data) {
        st_name = elf_data.get_next_n_bytes(4);
        st_value = elf_data.get_next_n_bytes(4);
        st_size = elf_data.get_next_n_bytes(4);
        st_info = elf_data.get_next_byte();
        st_other = elf_data.get_next_byte();
        st_shndx = elf_data.get_next_n_bytes(2);
        st_type = st_info & 0xf;
        st_bind = st_info >> 4;
        st_vis_txt = StHelpers::get_visibility(st_other);
        st_index_txt = StHelpers::get_index(st_shndx);
        st_type_txt = StHelpers::get_type(st_type);
        st_bind_txt = StHelpers::get_bind(st_bind);

    };
};

class Printer {
private:
    static std::string head;

public:
    static void print_symtab(const std::vector<SymbOfSymbolTable>& syms) {
        std::cout << head << std::endl;
        for (int i = 0; i < syms.size(); i++) {
            std::string buffer(100 + syms[i].name.size(), '\0');
            snprintf(&(buffer[0]), 100 + syms[i].name.size(), "[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s",
                i,
                syms[i].st_value,
                syms[i].st_size,
                syms[i].st_type_txt.c_str(),
                syms[i].st_bind_txt.c_str(),
                syms[i].st_vis_txt.c_str(),
                syms[i].st_index_txt.c_str(),
                syms[i].name.c_str());
            int j = buffer.size() - 1;
            while (buffer[j--] == '\0')
                buffer.pop_back();
            std::cout << buffer << std::endl;
        }
    };
    static std::string format_lable() {
        return "";
    }

    static std::string format_0_arg(std::string inst_name) {
        return "   " + inst_name;
    }

    static std::string format_2_arg(std::string inst_name, std::string dest, std::string source) {
        int size = 50 + dest.size() + source.size();
        std::string buffer(size, '\0');
        snprintf(&(buffer[0]), size, "%7s\t%s, %s", inst_name.c_str(), dest.c_str(), source.c_str());
        int i = buffer.size() - 1;
        while (buffer[i--] == '\0')
            buffer.pop_back();
        return buffer;
    }

    static std::string format_3_arg(std::string inst_name, std::string dest, std::string source1, std::string source2) {
        int size = 100 + dest.size() + source1.size() + source2.size();
        std::string buffer(size, '\0');
        snprintf(&(buffer[0]), size, "%7s\t%s, %s, %s", inst_name.c_str(), dest.c_str(), source1.c_str(), source2.c_str());
        int i = buffer.size() - 1;
        while (buffer[i--] == '\0')
            buffer.pop_back();
        return buffer;
    }

    static std::string format_load_store(std::string inst_name, std::string dest, std::string offset, std::string source) {
        int size = 100 + dest.size() + offset.size() + source.size();
        std::string buffer(size, '\0');
        snprintf(&(buffer[0]), size, "%7s\t%s, %s(%s)", inst_name.c_str(), dest.c_str(), offset.c_str(), source.c_str());
        int i = buffer.size() - 1;
        while (buffer[i--] == '\0')
            buffer.pop_back();
        return buffer;
    }

    static std::string get_hex(int32_t dec_num) {
        int size = std::to_string(dec_num).size() + 10;
        std::string buffer(size, '\0');
        snprintf(&(buffer[0]), size, "%x", dec_num);
        int i = buffer.size() - 1;
        while (buffer[i--] == '\0')
            buffer.pop_back();
        return buffer;
    }

};