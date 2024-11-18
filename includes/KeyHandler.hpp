#pragma once

#include <string>

namespace keyHandler
{
class KeyHandler
{
public:
    KeyHandler(const std::string& key);

    std::string getFirstKey() const;
    std::string getSecondKey() const;
    std::string getThirdKey() const;

private:
    void hashKey();

    std::string key;
};
} // namespace keyHandler
