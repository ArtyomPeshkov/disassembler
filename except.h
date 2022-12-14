#pragma once
#include <iostream>
#include <string>

struct IO_Exception : public std::logic_error {
    explicit IO_Exception(const std::string& reason) : std::logic_error(reason) {}
};

struct ELF_Data_Exception : public std::logic_error {
    explicit ELF_Data_Exception(const std::string& reason) : std::logic_error(reason) {}
};
