#ifndef _FileIoUtils_H_
#define _FileIoUtils_H_

#include <string>


class FileIoUtils
{
public:
    bool getFileContents(const std::string& filename, std::string& fileContent);
    bool dumpToFile(const std::string& filename, const std::string& fileContent);
};

#endif // _FileIoUtils_H_
