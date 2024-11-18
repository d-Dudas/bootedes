#include <getopt.h>
#include <iostream>

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
    const std::string programName = argv[0];
    std::cout << "Usage: " << programName
              << "[-(d/e) <inputfile>] [-o <outputfile>] [-p "
                 "<passphrase>] [-k <keyfile>]\n";
    std::cout << "Types: [\"des\", \"aes_128\", \"aes_192\", \"aes_256\", \"rsa\"]\n";

    std::cout << "\nExample for RSA key generation:\n";
    std::cout << programName << " -t rsa -k keyfile\n";

    std::cout << "\nExample for RSA encryption:\n";
    std::cout << programName << " -t rsa -e inputfile [-o outputfile] -k keyfile\n";

    std::cout << "\nExample for AES encryption:\n";
    std::cout << programName << " -t aes_128 -e inputfile [-o outputfile] -p passphrase\n";
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

bool OptionParser::validateOptions()
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

    if (ioConfig.outputFile.empty())
    {
        ioConfig.outputFile = ioConfig.inputFile + ".out";
    }

    if (not hasInputFile())
    {
        printUsage();
        return invalidOptions;
    }

    if (not hasPassword())
    {
        printUsage();
        return invalidOptions;
    }

    return validOptions;
}
