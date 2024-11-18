#include <getopt.h>
#include <iostream>
#include <fstream>
#include <sstream>

#include "OptionParser.hpp"

namespace
{
constexpr bool validOptions{true};
constexpr bool invalidOptions{false};
} // namespace

OptionParser::OptionParser(int argc, char** argv, IOConfig& ioConfig)
: ioConfig(ioConfig),
  argc(argc),
  argv(argv)
{
}

void OptionParser::printUsage() const
{
    const std::string programName{argv[0]};
    std::cout << "Usage: " << programName
              << " [-(d/e) <inputfile>] [-o <outputfile>] [-p "
                 "<passphrase>] [-k <keyfile>]\n";

    std::cout << "\nExample for encryption:\n";
    std::cout << programName << " -e inputfile [-o outputfile] -p passphrase\n";
}

bool OptionParser::hasKeyFile() const
{
    return not ioConfig.keyFile.empty();
}

bool OptionParser::hasPassword() const
{
    return not ioConfig.password.empty();
}

bool OptionParser::hasInputFile() const
{
    return not ioConfig.inputFile.empty();
}

bool OptionParser::readOptions()
{
    int opt;
    while ((opt = getopt(argc, argv, "d:e:o:p:k:h")) != -1)
    {
        switch (opt)
        {
            case 'd':
            {
                ioConfig.inputFile = optarg;
                ioConfig.operation = Operations::decrypt;
                break;
            }
            case 'e':
            {
                ioConfig.inputFile = optarg;
                ioConfig.operation = Operations::encrypt;
                break;
            }
            case 'o':
            {
                ioConfig.outputFile = optarg;
                break;
            }
            case 'p':
            {
                ioConfig.password = optarg;
                break;
            }
            case 'k':
            {
                ioConfig.keyFile = optarg;
                break;
            }
            case 'h':
            {
                printUsage();
                return validOptions;
            }
            default:
            {
                printUsage();
                return invalidOptions;
            }
        }
    }

    return validOptions;
}

void OptionParser::readPasswordFromKeyFile()
{
    std::ifstream keyFileStream(ioConfig.keyFile);
    if (keyFileStream)
    {
        std::stringstream buffer;
        buffer << keyFileStream.rdbuf();
        ioConfig.password = buffer.str();
    }
    else
    {
        std::cerr << "Error: Unable to open key file: " << ioConfig.keyFile << std::endl;
    }
}

bool OptionParser::validateOptions()
{
    if (not readOptions())
    {
        return invalidOptions;
    }

    if (ioConfig.outputFile.empty())
    {
        ioConfig.outputFile = ioConfig.inputFile + ".out";
    }

    if (not hasInputFile())
    {
        printUsage();
        return invalidOptions;
    }

    if (hasKeyFile())
    {
        readPasswordFromKeyFile();
    }

    if (not hasPassword())
    {
        printUsage();
        return invalidOptions;
    }

    return validOptions;
}
