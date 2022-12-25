#include <fstream>
#include <sstream>
#include <jwt-cpp/jwt.h>
#include <FileIoUtils.h>


std::string FileIoUtils::getFileContents(const std::string& filename) {
    std::ifstream file(filename.c_str());

    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file  " + filename);
    }
    
    std::stringstream contentStream;
    contentStream << file.rdbuf();
    std::string fileContent = contentStream.str();
    fileContent.pop_back(); // drop newline at eof
    return fileContent;
}

void FileIoUtils::dumpToFile(const std::string& filename, const std::string& fileContent) {
    std::ofstream file(filename.c_str());

    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file  " + filename);
    }
    
    file << fileContent;
}
