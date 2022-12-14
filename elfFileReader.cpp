#include "elfFileReader.h"
#include "except.h"
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

void ElfFileReader::parseClassDataVerExcept(std::string fail, std::string ok, std::string unknown, uint8_t to_check){
	if (to_check == 0)
		throw IO_Exception(fail);
	else if (to_check == 2)
		throw IO_Exception(ok);
	else if (to_check != 1)
		throw IO_Exception(unknown);
}

uint32_t ElfFileReader::byte_vec_2_int(std::vector<uint8_t> bytes)
{
	uint64_t res = 0;
	for (int i = 0; i < bytes.size(); i++)
		res += (bytes[i] << (i * 8));
	return res;
}

ElfFileReader::ElfFileReader(std::string input_file) {
	//если файл не найден, обра
	my_file.open(input_file, std::ios::binary | std::ios::in);

	if (!my_file)
		throw IO_Exception("File failed to open");

	if (get_next_n_bytes(4) != 0x464C457f)
		throw IO_Exception("Not elf file");
	int ei_class_byte = get_next_byte();
	int ei_data_byte = get_next_byte();
	int ei_version_byte = get_next_byte();
	seek(18);
	int e_machine_bytes = get_next_n_bytes(2);
	int e_version_bytes = get_next_n_bytes(4);
	parseClassDataVerExcept("elf class none","elf class 64", "unknown elf class", ei_class_byte);
	parseClassDataVerExcept("elf data none", "elf data 2msb", "unknown elf class", ei_data_byte);
	parseClassDataVerExcept("e version is invalid", "unknown e version", "unknown e version", ei_version_byte);
	if (e_machine_bytes != 0xF3)
		throw IO_Exception("Not RISC-V architecture");
	if (e_version_bytes != 1)
		throw IO_Exception("e version none (invalid value)");
}


uint8_t ElfFileReader::get_next_byte() {
	uint8_t reader;
	my_file.read(reinterpret_cast<char*>(&reader), 1);
	return reader;
}

/*
Can't read more than 4 byte
*/

uint32_t ElfFileReader::get_next_n_bytes(int num_of_bytes) {
	std::vector<uint8_t> byteHolder(num_of_bytes);
	my_file.read(reinterpret_cast<char*>(&byteHolder[0]), num_of_bytes);
	return byte_vec_2_int(byteHolder);
}

void ElfFileReader::seek(int index_of_byte) {
	my_file.seekg(index_of_byte, std::ios::beg);
}

int ElfFileReader::tell() {
	return my_file.tellg();
}

void ElfFileReader::close_file(){
	my_file.close();
}
