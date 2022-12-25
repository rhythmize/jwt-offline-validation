#ifndef _FileIoUtils_H_
#define _FileIoUtils_H_

#include <string>

class FileIoUtils
{
public:
    static std::string getFileContents(const std::string& filename);
    static void dumpToFile(const std::string& filename, const std::string& fileContent);
};

#endif // _FileIoUtils_H_
