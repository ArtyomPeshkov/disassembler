#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <map>
#include <cstdio>


class ElfParser {
private:
    static std::string reg_name(uint8_t reg) {
        if (reg == 0)
            return "zero";
        else if (reg == 1)
            return "ra";
        else if (reg == 2)
            return "sp";
        else if (reg == 3)
            return "gp";
        else if (reg == 4)
            return "tp";
        else if (reg >= 5 && reg <= 7)
            return "t" + std::to_string(reg - 5);
        else if (reg >= 8 && reg <= 9)
            return "s" + std::to_string(reg - 8);
        else if (reg >= 10 && reg <= 17)
            return "a" + std::to_string(reg - 10);
        else if (reg >= 18 && reg <= 27)
            return "s" + std::to_string(reg - 16);
        else if (reg >= 28 && reg <= 31)
            return "t" + std::to_string(reg - 25);
        return "UNKNOWN REG";
    }

public:
    int mark_cnt = 0;
    void parse(std::string input_file_name, std::ofstream& output);
    std::string recognize_and_print_instruct(uint32_t command_data, uint32_t command_addr, std::map<uint32_t, std::string>& marks);

};

