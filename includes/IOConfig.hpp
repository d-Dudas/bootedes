#pragma once

#include <string>

#include "Operations.hpp"

struct IOConfig
{
    std::string inputFile;
    std::string outputFile;
    std::string keyFile;
    std::string password;
    std::string firstRoundPassword;
    std::string secondRoundPassword;
    std::string thirdRoundPassword;
    Operations operation{Operations::invalid};
};
