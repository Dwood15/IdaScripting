/*
*	From: IDA Scripting Repository
*	Copyright 2018 by Dason Woodhouse (Dwood15)
*/
#include <idc.idc>

static getFuncName(ea) {
	    auto funcName = get_func_name(ea);
		
		auto dm = demangle_name(funcName, get_inf_attr(INF_LONG_DN));
		if(dm != 0) {
			funcName = dm;
		}
		return funcName;
}

//Dumps ida-defined functions to an large array of defined_functionrange structures for use in Binary//Nearest Neighbor searches.
//Can be useful for adding an embedded debugger.
static functionDump(ea) {
	auto funcName = 0;

	auto end = 0x0;
	
	auto file_open = get_idb_path()[0:-4] + "_afuncdump.cpp";
    auto stream = fopen(file_open, "w");
	
	auto peekAhead;

	auto total = 0;
	
	auto includes = "#pragma once\n#include <array>\n";
	auto typedefs = "typedef unsigned int uintptr_t;\n";
	auto memoryMapHeader = "struct defined_functionrange {\n\tuintptr_t begin;\n\tconst char* functionName;\n\tuintptr_t end;\n";
    auto lt_operator = "\tbool operator<(defined_functionrange const &other) { return begin < other.end; }\n";
	auto gt_operator = "\tbool operator>(defined_functionrange const &other) { return begin > other.end; }\n";
	auto eq_operator = "\tbool operator==(defined_functionrange const &other) { return end == other.end && begin == other.begin; }\n";
	auto contains = "\tbool contains(uintptr_t const &other) { return ( other <= begin && other >= end ); }\n};\n";
	
	fprintf(stream, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n", includes, typedefs, memoryMapHeader, lt_operator, gt_operator, eq_operator, contains);
	
	fprintf(stream, "std::array<defined_functionrange, > knownfunctionlist = {{ \n");
	
	while( ea != BADADDR ) {
		ea = NextFunction(ea);		
		peekAhead = NextFunction(ea);
        end = FindFuncEnd(ea);	
		funcName = getFuncName(ea);
		++total;
		
		if(peekAhead == BADADDR) {
			fprintf(stream, "\t{ 0x%X, \"%s\", 0x%X }\n", ea, funcName, end);
			ea = peekAhead;
			continue;
		}
		//This 'globs' non-defined functions and alignment bytes into the current function for faster searching.
		//The goal is to get 'cloase enough', not exactness. 
		end = peekAhead - 1;		
		fprintf(stream, "\t{ 0x%X, \"%s\", 0x%X },\n", ea, funcName, end);
    }
	
	fprintf(stream, "}};\n");
	fprintf(stream, "/t/***** TOTAL ELEMENTS: %d *****/", total);	
	fprintf(stream, "//Hint: add to the array's template above.", total);
	fclose(stream);
}

static main() {
	//Generic starting address for function x86 .TEXT portion of programs.
	auto start = 0x40000;
	functionDump(start);
	//TODO: Dump Xrefs into a reasonably fast structure.
}
