#pragma once

#include "IOConfig.hpp"

class OptionParser
{
public:
    OptionParser(int argc, char** argv, IOConfig& ioConfig);
    bool validateOptions();

private:
    void printUsage() const;
    bool isDES() const;
    bool isAES() const;
    bool isRSA() const;
    bool hasKeyFile() const;
    bool hasPassword() const;
    bool hasInputFile() const;

    IOConfig& ioConfig;
    int argc;
    char** argv;
};
