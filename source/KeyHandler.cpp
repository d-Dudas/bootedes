#include "KeyHandler.hpp"

#include <openssl/evp.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstdint>

namespace
{
constexpr std::uint8_t firstKeyLenght{8u};
constexpr std::uint8_t secondKeyLenght{16u};
constexpr std::uint8_t thirdKeyLenght{8u};
} // namespace

namespace keyHandler
{
KeyHandler::KeyHandler(const std::string& key)
: key{key}
{
    hashKey();
}

std::string KeyHandler::getFirstKey() const
{
    return key.substr(0, firstKeyLenght);
}

std::string KeyHandler::getSecondKey() const
{
    return key.substr(firstKeyLenght, secondKeyLenght);
}

std::string KeyHandler::getThirdKey() const
{
    return key.substr(firstKeyLenght + secondKeyLenght, thirdKeyLenght);
}

void KeyHandler::hashKey()
{
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr)
    {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    const EVP_MD* md = EVP_sha256();
    if (EVP_DigestInit_ex(context, md, nullptr) != 1)
    {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    if (EVP_DigestUpdate(context, key.data(), key.size()) != 1)
    {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len{0u};

    if (EVP_DigestFinal_ex(context, hash, &hash_len) != 1)
    {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(context);
    std::ostringstream oss;
    for (unsigned int i{0u}; i < 16; ++i)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    key = oss.str();
}
} // namespace keyHandler