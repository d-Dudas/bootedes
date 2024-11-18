#pragma once

#include <cstdint>

enum class Operations : std::uint8_t
{
    encrypt,
    decrypt,

    invalid
};
