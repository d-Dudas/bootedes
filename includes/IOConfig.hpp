#pragma once

#include <string>

#include "Operations.hpp"

struct IOConfig
{
    std::string inputFile;
    std::string outputFile;
    std::string keyFile;
    std::string password;
    Operations operation{Operations::invalid};
};
