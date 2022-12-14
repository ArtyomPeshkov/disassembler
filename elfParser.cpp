#include "elfParser.h"
#include "elfFileReader.h"
#include "sectionTable.h"
#include "Utility.h"
#include "except.h"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>


void ElfParser::parse(std::string input_file_name, std::ofstream& output) {
	ElfFileReader elf_data = ElfFileReader(input_file_name);
	elf_data.seek(32);

	//	Смещение таблицы заголовков секций от начала файла в байтах. Если у файла нет таблицы заголовков секций, это поле содержит 0.
	uint32_t e_shoff = elf_data.get_next_n_bytes(4);

	elf_data.seek(46);
	// Размер одного заголовка секции. Все заголовки секций имеют одинаковый размер (40 для 32-битных файлов и 64 для 64-битных).
	uint32_t e_shentsize = elf_data.get_next_n_bytes(2);

	if (e_shentsize != 40)
		throw ELF_Data_Exception("Unexpectedly e_shentsize not equal 40");

	// Число заголовков секций. Если у файла нет таблицы заголовков секций, это поле содержит 0.
	uint32_t e_shnum = elf_data.get_next_n_bytes(2);

	if (e_shnum == 0)
		throw ELF_Data_Exception("No table section header found");

	// Индекс записи в таблице заголовков секций, описывающей таблицу названий секций (обычно эта таблица называется .shstrtab и представляет собой отдельную секцию). Если файл не содержит таблицы названий секций, это поле содержит 0.
	uint32_t e_shstrndx = elf_data.get_next_n_bytes(2);

	if (e_shstrndx == 0)
		throw ELF_Data_Exception("No .shstrtab found");

	//working with .shstrtab

	// начало блока .shstrtab в таблице заголовков секций
	elf_data.seek(e_shoff + e_shentsize * e_shstrndx);
	FieldOfHeaderSectionTable shstrtab(elf_data);
	FieldOfHeaderSectionTable text_section;
	SectionDataStrtab strtab_section;
	std::vector<SymbOfSymbolTable> symbs;
	std::vector<uint32_t> commands;
	std::map<uint32_t, std::string> marks;
	for (int k = 0; k < e_shnum; k++) {
		elf_data.seek(e_shoff + k * e_shentsize);
		FieldOfHeaderSectionTable section_header(elf_data);

		std::string section_name = "";
		char chr;
		elf_data.seek(shstrtab.sh_offset + section_header.sh_name);
		while ((chr = elf_data.get_next_byte()) > 0)
			section_name += chr;

		if (section_name == ".strtab") {
			std::string section_data = "";
			elf_data.seek(section_header.sh_offset);
			for (int i = 0; i < section_header.sh_size; i++)
				section_data += (elf_data.get_next_byte());
			strtab_section = SectionDataStrtab(section_data, section_header);
		}
		else if (section_name == ".symtab") {
			elf_data.seek(section_header.sh_offset);
			for (int j = 0; j < section_header.sh_size/16; j ++)
				symbs.push_back(SymbOfSymbolTable(elf_data));
		}
		else if (section_name == ".text") {
			elf_data.seek(section_header.sh_offset);
			for (int j = 0; j < section_header.sh_size / 4; j++)
				commands.push_back(elf_data.get_next_n_bytes(4));
			text_section = section_header;
		}
	}
	elf_data.close_file();

	for (int i = 0; i < symbs.size(); i++) {
		symbs[i].name = strtab_section.get_name(symbs[i].st_name);
		if (symbs[i].st_type_txt == "FUNC")
			marks.insert({ symbs[i].st_value, ((symbs[i].name != "") ? symbs[i].name : ("L" + std::to_string(mark_cnt++))) });
	}
	output << ".text" << std::endl;
	for (int i = 0; i < commands.size(); i++) {
		auto mark = marks.find(text_section.sh_addr + i * 4);
		uint32_t addr_val = text_section.sh_addr + i * 4;
		if (mark != marks.end()){
			//"%08x   <%s>:\n"
			int size = 15 + mark->second.size();
			std::string marker(size, '\0');
			snprintf(&(marker[0]), size, "%08x   <%s>:\n", addr_val, (mark -> second).c_str());
			int j = marker.size() - 1;
			while (marker[j--] == '\0')
				marker.pop_back();
			output << marker << std::endl;
		}
		//"   %05x:\t%08x\t"
		int size = 50;
		std::string addr(size, '\0');
		snprintf(&(addr[0]), size, "   %05x:\t%08x\t", addr_val, commands[i]);
		int j = addr.size() - 1;
		while (addr[j--] == '\0')
			addr.pop_back();
		output << addr << recognize_and_print_instruct(commands[i], addr_val, marks) << std::endl;
	}
	output << std::endl;
	output << ".symtab" << std::endl;
	output << "Symbol Value              Size Type     Bind     Vis       Index Name" << std::endl;
	for (int i = 0; i < symbs.size(); i++) {
		std::string buffer(100 + symbs[i].name.size(), '\0');
		snprintf(&(buffer[0]), 100 + symbs[i].name.size(), "[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s",
		i,
		symbs[i].st_value,
		symbs[i].st_size,
		symbs[i].st_type_txt.c_str(),
		symbs[i].st_bind_txt.c_str(),
		symbs[i].st_vis_txt.c_str(),
		symbs[i].st_index_txt.c_str(),
		symbs[i].name.c_str());
		int j = buffer.size() - 1;
		while (buffer[j--] == '\0')
			buffer.pop_back();
		output << buffer << std::endl;
	}
}

std::string ElfParser::recognize_and_print_instruct(uint32_t command_data, uint32_t command_addr, std::map<uint32_t, std::string>& marks)
{
	
	uint8_t opcode = command_data & 0x7f;
	uint8_t rd___imm_4_0 = (command_data >> 7) & 0x1f;
	uint8_t funct3 = (command_data >> 12) & 0x7;
	uint8_t rs1 = (command_data >> 15) & 0x1f;
	uint8_t rs2___shamt = (command_data >> 20) & 0x1f;
	uint16_t imm_11_0 = command_data >> 20;
	int16_t signed_imm_11_0 = ((int16_t)imm_11_0) - (imm_11_0 >> 11) * 2 * (1 << 11);
	uint8_t imm_11_5 = command_data >> 25;
	if (opcode == 0b0110111 || opcode == 0b0010111)
	{
		uint32_t imm_31_12 = (command_data >> 12);
		uint32_t imm = imm_31_12;
		if (opcode == 0b0110111)
			return Printer::format_2_arg("lui", reg_name(rd___imm_4_0), std::to_string(imm));
		else
			return Printer::format_2_arg("auipc", reg_name(rd___imm_4_0), std::to_string(imm));
	} else if (opcode == 0b1101111) {
		uint8_t imm_20 = (command_data >> 31) & 1;
		uint16_t imm_10_1 = (command_data >> 21) & 0x3ff;
		uint8_t imm_11 = (command_data >> 20) & 1;
		uint16_t imm_19_12 = (command_data >> 12) & 0xff;
		int32_t imm = (imm_20 << 20 | imm_19_12 << 12 | imm_11 << 11 | imm_10_1 << 1) - imm_20 * 2 * (1 << 20);
		uint32_t new_addr = command_addr + imm;
		auto mark = marks.find(new_addr);
		std::string mark_str;
		if (mark != marks.end())
			mark_str = mark->second;
		else {
			mark_str = "L" + std::to_string(mark_cnt++);
			marks.insert({ new_addr, mark_str });
		}
		return Printer::format_2_arg("jal", reg_name(rd___imm_4_0), ("0x" + Printer::get_hex(new_addr) + " <" + mark_str + ">"));
	} else if (opcode == 0b1100111)
		return Printer::format_load_store("jalr", reg_name(rd___imm_4_0),std::to_string(signed_imm_11_0), reg_name(rs1));
	else if (opcode == 0b1100011) {
		uint8_t imm_12 = imm_11_5 >> 6;
		uint8_t imm_10_5 = imm_11_5 & 0x3f;
		uint8_t imm_4_1 = rd___imm_4_0 >> 1;
		uint8_t imm_11 = rd___imm_4_0 & 1;
		int32_t imm = (imm_12 << 12 | imm_11 << 11 | imm_10_5 << 5 | imm_4_1 << 1) - imm_12 * 2 * (1 << 12);
		uint32_t new_addr = command_addr + imm;
		auto mark = marks.find(new_addr);
		std::string mark_str;
		if (mark != marks.end())
			mark_str = mark->second;
		else {
			mark_str = "L" + std::to_string(mark_cnt++);
			marks.insert({ new_addr, mark_str });
		}
			
		if (funct3 == 0b000)
			return Printer::format_3_arg("beq", reg_name(rs1), reg_name(rs2___shamt), ("0x" + Printer::get_hex(new_addr) + " <" + mark_str + ">"));
		else if (funct3 == 0b001)
			return Printer::format_3_arg("bne", reg_name(rs1), reg_name(rs2___shamt), ("0x" + Printer::get_hex(new_addr) + " <" + mark_str + ">"));
		else if (funct3 == 0b100)
			return Printer::format_3_arg("blt", reg_name(rs1), reg_name(rs2___shamt), ("0x" + Printer::get_hex(new_addr) + " <" + mark_str + ">"));
		else if (funct3 == 0b101)
			return Printer::format_3_arg("bge", reg_name(rs1), reg_name(rs2___shamt), ("0x" + Printer::get_hex(new_addr) + " <" + mark_str + ">"));
		else if (funct3 == 0b110)
			return Printer::format_3_arg("bltu", reg_name(rs1), reg_name(rs2___shamt), ("0x" + Printer::get_hex(new_addr) + " <" + mark_str + ">"));
		else if (funct3 == 0b111)
			return Printer::format_3_arg("bgeu", reg_name(rs1), reg_name(rs2___shamt), ("0x" + Printer::get_hex(new_addr) + " <" + mark_str + ">"));
	} else if (opcode == 0b0000011) {
		if (funct3 == 0b000)
			return Printer::format_load_store("lb", reg_name(rd___imm_4_0), std::to_string(signed_imm_11_0), reg_name(rs1));
		else if (funct3 == 0b001)
			return Printer::format_load_store("lh", reg_name(rd___imm_4_0), std::to_string(signed_imm_11_0), reg_name(rs1));
		else if (funct3 == 0b010)
			return Printer::format_load_store("lw", reg_name(rd___imm_4_0), std::to_string(signed_imm_11_0), reg_name(rs1));
		else if (funct3 == 0b100)
			return Printer::format_load_store("lbu", reg_name(rd___imm_4_0), std::to_string(signed_imm_11_0), reg_name(rs1));
		else if (funct3 == 0b101)
			return Printer::format_load_store("lhu", reg_name(rd___imm_4_0), std::to_string(signed_imm_11_0), reg_name(rs1));
	} else if (opcode == 0b0100011) {
		int32_t imm = ((uint16_t)imm_11_5 << 5 | rd___imm_4_0) - (imm_11_5 >> 6) * 2 * (1 << 11);
		if (funct3 == 0b000)
			return Printer::format_load_store("sb", reg_name(rs2___shamt), std::to_string(imm), reg_name(rs1));
		else if (funct3 == 0b001)
			return Printer::format_load_store("sh", reg_name(rs2___shamt), std::to_string(imm), reg_name(rs1));
		else if (funct3 == 0b010)
			return Printer::format_load_store("sw", reg_name(rs2___shamt), std::to_string(imm), reg_name(rs1));
	} else if (opcode == 0b0010011) {
		if (funct3 == 0b000)
			return Printer::format_3_arg("addi", reg_name(rd___imm_4_0) ,reg_name(rs1), std::to_string(signed_imm_11_0));
		else if (funct3 == 0b001)
			return Printer::format_3_arg("slli", reg_name(rd___imm_4_0), reg_name(rs1), std::to_string(rs2___shamt));
		else if (funct3 == 0b010)
			return Printer::format_3_arg("slti", reg_name(rd___imm_4_0), reg_name(rs1), std::to_string(signed_imm_11_0));
		else if (funct3 == 0b011)
			return Printer::format_3_arg("sltiu", reg_name(rd___imm_4_0), reg_name(rs1), std::to_string(signed_imm_11_0));
		else if (funct3 == 0b100)
			return Printer::format_3_arg("xori", reg_name(rd___imm_4_0), reg_name(rs1), std::to_string(signed_imm_11_0));
		else if (funct3 == 0b101) {
			if (imm_11_5 == 0b0000000)
				return Printer::format_3_arg("srli", reg_name(rd___imm_4_0), reg_name(rs1), std::to_string(rs2___shamt));
			else if (imm_11_5 == 0b0100000)
				return Printer::format_3_arg("srai", reg_name(rd___imm_4_0), reg_name(rs1), std::to_string(rs2___shamt));
		}
		else if (funct3 == 0b110)
				return Printer::format_3_arg("ori", reg_name(rd___imm_4_0), reg_name(rs1), std::to_string(signed_imm_11_0));
		else if (funct3 == 0b111)
				return Printer::format_3_arg("andi", reg_name(rd___imm_4_0), reg_name(rs1), std::to_string(signed_imm_11_0));
	} else if (opcode == 0b0110011) {
		if (funct3 == 0b000)
			if (imm_11_5 == 0b0000000)
				return Printer::format_3_arg("add", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
			else if (imm_11_5 == 0b0100000)
				return Printer::format_3_arg("sub", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
			else if (imm_11_5 == 0b0000001)
				return Printer::format_3_arg("mul", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
		if (funct3 == 0b001)
			if (imm_11_5 == 0b0000000)
				return Printer::format_3_arg("sll", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
			else if (imm_11_5 == 0b0000001)
				return Printer::format_3_arg("mulh", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
		if (funct3 == 0b010)
			if (imm_11_5 == 0b0000000)
				return Printer::format_3_arg("slt", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
			else if (imm_11_5 == 0b0000001)
				return Printer::format_3_arg("mulhsu", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
		if (funct3 == 0b011)
			if (imm_11_5 == 0b0000000)
				return Printer::format_3_arg("sltu", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
			else if (imm_11_5 == 0b0000001)
				return Printer::format_3_arg("mulhu", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
		if (funct3 == 0b100)
			if (imm_11_5 == 0b0000000)
				return Printer::format_3_arg("xor", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
			else if (imm_11_5 == 0b0000001)
				return Printer::format_3_arg("div", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
		if (funct3 == 0b101)
			if (imm_11_5 == 0b0000000)
				return Printer::format_3_arg("srl", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
			else if (imm_11_5 == 0b0100000)
				return Printer::format_3_arg("sra", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
			else if (imm_11_5 == 0b0000001)
				return Printer::format_3_arg("divu", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
		if (funct3 == 0b110)
			if (imm_11_5 == 0b0000000)
				return Printer::format_3_arg("or", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
			else if (imm_11_5 == 0b0000001)
				return Printer::format_3_arg("rem", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
		if (funct3 == 0b111)
			if (imm_11_5 == 0b0000000)
				return Printer::format_3_arg("and", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
			else if (imm_11_5 == 0b0000001)
				return Printer::format_3_arg("remu", reg_name(rd___imm_4_0), reg_name(rs1), reg_name(rs2___shamt));
	} else if (opcode == 0b1110011) {
		if (imm_11_0 == 0b000000000000)
			return Printer::format_0_arg("ecall");
		if (imm_11_0 == 0b000000000001)
			return Printer::format_0_arg("ebreak");
	}
	
	return Printer::format_0_arg("unknown_instruction");
}

