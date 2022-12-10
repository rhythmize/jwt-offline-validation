#include <fstream>
#include <iostream>
#include <sstream>
#include <jwt-cpp/jwt.h>
#include <TokenHelper.h>


bool TokenHelper::getFileContents(const std::string& filename, std::string& fileContent) {
    std::ifstream file(filename.c_str());

    if (!file.is_open()) {
        std::cout << "Cannot open file " << filename << "\n";
        return false;
    }
    
    std::stringstream contentStream;
    contentStream << file.rdbuf();
    fileContent = contentStream.str();
    fileContent.pop_back();
    return true;
}

bool TokenHelper::dumpToFile(const std::string& filename, const std::string& fileContent) {
    std::ofstream file(filename.c_str());

    if (!file.is_open()) {
        std::cout << "Cannot open file " << filename << "\n";
        return false;
    }
    
    file << fileContent;
    return true;
}
