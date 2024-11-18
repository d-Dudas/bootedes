#include <cstdint>

#include "IOConfig.hpp"
#include "OptionParser.hpp"
#include "KeyHandler.hpp"
#include "aes/AES.hpp"
#include "des/DES.hpp"

namespace
{
constexpr std::uint8_t success{0};
constexpr std::uint8_t failure{1};
const std::string firstProcessOutput{"tmp.first"};
const std::string secondProcessOutput{"tmp.second"};

bool deleteTemporaryFiles()
{
    return not (std::remove(firstProcessOutput.c_str()) != 0 or std::remove(secondProcessOutput.c_str()) != 0);
}
} // namespace

int main(int argc, char* argv[])
{
    IOConfig config{};
    OptionParser parser(argc, argv, config);

    if (not parser.validateOptions())
    {
        return failure;
    }

    keyHandler::KeyHandler keyHandler{config.password};
    des::DES des{};
    aes::AES aes{};

    switch (config.operation)
    {
        case Operations::encrypt:
            des.encrypt(config.inputFile, firstProcessOutput, keyHandler.getFirstKey());
            aes.encrypt(firstProcessOutput, secondProcessOutput, keyHandler.getSecondKey());
            des.encrypt(secondProcessOutput, config.outputFile, keyHandler.getThirdKey());
            break;
        case Operations::decrypt:
            des.decrypt(config.inputFile, firstProcessOutput, keyHandler.getThirdKey());
            aes.decrypt(firstProcessOutput, secondProcessOutput, keyHandler.getSecondKey());
            des.decrypt(secondProcessOutput, config.outputFile, keyHandler.getFirstKey());
            break;
        case Operations::invalid:
            return failure;
    }

    return deleteTemporaryFiles() ? success : failure;
}
