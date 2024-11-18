#pragma once

#include <bitset>
#include <string>
#include <vector>
#include "Operations.hpp"

namespace des
{
class DES
{
public:
    void encrypt(const std::string& inputFile, const std::string& outputFile, std::string password);
    void decrypt(const std::string& inputFile, const std::string& outputFile, std::string password);

private:
    std::bitset<56> initialKeyPermutation(const std::bitset<64>& key) const;
    std::bitset<28> leftCircularShift(std::bitset<28>& halfKey, int shifts) const;
    std::vector<std::bitset<48>> generateKeys(const std::bitset<64>& key) const;
    std::bitset<64> keyStringToBitset(std::string& keyStr) const;
    std::bitset<32> feistelFunction(const std::bitset<32>& halfBlock, const std::bitset<48>& key) const;
    std::bitset<64> applyPermutations(std::bitset<64>& block, std::vector<std::bitset<48>>& subKeys) const;
    void applyFeistelFunction(std::bitset<64>& permutedBlock, std::vector<std::bitset<48>>& subKeys) const;
    std::bitset<48> createExpandedBlock(const std::bitset<32>& halfBlock) const;
    std::bitset<32> applySubstitutionBoxesPermutations(const std::bitset<48>& xored) const;
    std::bitset<32> applyFinalPermutation(const std::bitset<32>& block) const;
    std::bitset<64> applyInitialPermutation(const std::bitset<64>& block) const;
    std::bitset<64> applyInversePermutation(const std::bitset<64>& permutedBlock) const;
    void applyPermutationsOnChunks(
        const std::string& inputFile,
        const std::string& outputFile,
        std::vector<std::bitset<48>>& subKeys) const;
    std::bitset<64> convertCharBufferToBitset(const char* buffer, int bufferSize) const;
    void addPaddingToBitset(std::bitset<64>& block, int originalSize) const;
    int removePaddingFromBitset(std::bitset<64>& block) const;
    void adjustKeySize(std::string& key) const;

    Operations operation{Operations::invalid};
};
} // namespace des
