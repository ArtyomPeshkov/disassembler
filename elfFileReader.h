#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <vector>

class ElfFileReader {
private:
	std::ifstream my_file;
	void parseClassDataVerExcept(std::string, std::string, std::string, uint8_t);
	uint32_t byte_vec_2_int(std::vector<uint8_t>);
public:
	ElfFileReader() = default;
	ElfFileReader(std::string input_file);
	void seek(int index_of_byte);
	int tell();
	uint8_t get_next_byte();
	uint32_t get_next_n_bytes(int num_of_bytes);
	void close_file();
};

