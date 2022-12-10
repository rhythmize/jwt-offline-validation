#ifndef _TokenHelper_H_
#define _TokenHelper_H_

#include <string>


class TokenHelper
{
public:
    bool getFileContents(const std::string& filename, std::string& fileContent);
    bool dumpToFile(const std::string& filename, const std::string& fileContent);
};

#endif // _TokenHelper_H_
