#include <algorithm>
#include <fstream>
#include <iostream>

#include "des/DES.hpp"
#include "des/Structures.hpp"
#include "Operations.hpp"

namespace des
{
std::bitset<56> DES::initialKeyPermutation(const std::bitset<64>& key) const
{
    std::bitset<56> permutedKey;
    for (int i = 0; i < 56; i++)
    {
        permutedKey[55 - i] = key[64 - PC1[i]];
    }
    return permutedKey;
}

std::bitset<28> DES::leftCircularShift(std::bitset<28>& halfKey, int shifts) const
{
    return (halfKey << shifts) | (halfKey >> (28 - shifts));
}

std::vector<std::bitset<48>> DES::generateKeys(const std::bitset<64>& key) const
{
    std::bitset<56> permutedKey = initialKeyPermutation(key);
    std::bitset<28> left = std::bitset<28>((permutedKey >> 28).to_ulong());
    std::bitset<28> right = std::bitset<28>((permutedKey & std::bitset<56>(0x00FFFFFFF)).to_ulong());
    std::vector<std::bitset<48>> subKeys;

    for (int i = 0; i < 16; i++)
    {
        left = leftCircularShift(left, shifts[i]);
        right = leftCircularShift(right, shifts[i]);

        std::bitset<56> combinedKey = (std::bitset<56>(left.to_ulong()) << 28) | std::bitset<56>(right.to_ulong());
        std::bitset<48> compressedKey;
        for (int j = 0; j < 48; j++)
        {
            compressedKey[47 - j] = combinedKey[56 - PC2[j]];
        }
        subKeys.push_back(compressedKey);
    }
    return subKeys;
}

std::bitset<64> DES::keyStringToBitset(std::string& keyStr) const
{
    std::bitset<64> bitset;
    for (size_t i = 0; i < 8; i++)
    {
        std::bitset<8> charBits = std::bitset<8>(keyStr[i]);
        for (int j = 0; j < 8; j++)
        {
            bitset[64 - 8 * i + j - 1] = charBits[7 - j];
        }
    }

    return bitset;
}

std::bitset<48> DES::createExpandedBlock(const std::bitset<32>& halfBlock) const
{
    std::bitset<48> expandedBlock;
    for (int i = 0; i < 48; i++)
    {
        expandedBlock[47 - i] = halfBlock[32 - expansionTable[i]];
    }
    return expandedBlock;
}

std::bitset<32> DES::applySubstitutionBoxesPermutations(const std::bitset<48>& xored) const
{
    std::bitset<32> output;
    for (int i = 0; i < 8; i++)
    {
        int row = (xored[6 * i] << 1) + xored[6 * i + 5];
        int col = (xored[6 * i + 1] << 3) + (xored[6 * i + 2] << 2) + (xored[6 * i + 3] << 1) + xored[6 * i + 4];
        int num = substitutionBoxes[i][row][col];
        for (int j = 0; j < 4; j++)
        {
            output[4 * i + j] = (num >> (3 - j)) & 1;
        }
    }

    return output;
}

std::bitset<32> DES::applyFinalPermutation(const std::bitset<32>& block) const
{
    std::bitset<32> permuted;
    for (int i = 0; i < 32; i++)
    {
        permuted[31 - i] = block[32 - permutationTable[i]];
    }
    return permuted;
}

std::bitset<32> DES::feistelFunction(const std::bitset<32>& halfBlock, const std::bitset<48>& key) const
{
    std::bitset<48> expandedBlock = createExpandedBlock(halfBlock);
    std::bitset<48> xored = expandedBlock ^ key;
    std::bitset<32> output = applySubstitutionBoxesPermutations(xored);
    std::bitset<32> permuted = applyFinalPermutation(output);

    return permuted;
}

std::bitset<64> DES::applyInitialPermutation(const std::bitset<64>& block) const
{
    std::bitset<64> permutedBlock;
    for (int i = 0; i < 64; i++)
    {
        permutedBlock[63 - i] = block[64 - initialPermutationTable[i]];
    }

    return permutedBlock;
}

void DES::applyFeistelFunction(std::bitset<64>& permutedBlock, std::vector<std::bitset<48>>& subKeys) const
{
    std::bitset<32> left = std::bitset<32>((permutedBlock >> 32).to_ulong());
    std::bitset<32> right = std::bitset<32>((permutedBlock & std::bitset<64>(0xFFFFFFFF)).to_ulong());
    std::bitset<32> originalLeft;

    for (int i = 0; i < 16; i++)
    {
        originalLeft = left;
        left = right;
        right = originalLeft ^ feistelFunction(right, subKeys[i]);
    }

    permutedBlock = (std::bitset<64>(right.to_ulong()) << 32) | std::bitset<64>(left.to_ulong());
}

std::bitset<64> DES::applyInversePermutation(const std::bitset<64>& permutedBlock) const
{
    std::bitset<64> finalBlock;
    for (int i = 0; i < 64; i++)
    {
        finalBlock[63 - i] = permutedBlock[64 - inversePermutationTable[i]];
    }

    return finalBlock;
}

std::bitset<64> DES::applyPermutations(std::bitset<64>& block, std::vector<std::bitset<48>>& subKeys) const
{
    std::bitset<64> permutedBlock = applyInitialPermutation(block);
    applyFeistelFunction(permutedBlock, subKeys);
    std::bitset<64> finalBlock = applyInversePermutation(permutedBlock);

    return finalBlock;
}

std::bitset<64> DES::convertCharBufferToBitset(const char* buffer, int bufferSize) const
{
    std::bitset<64> block;
    for (int i = 0; i < bufferSize; ++i)
    {
        block = (block << 8) | std::bitset<64>(static_cast<unsigned char>(buffer[i]));
    }

    return block;
}

void DES::addPaddingToBitset(std::bitset<64>& block, int originalSize) const
{
    int paddingLength = 8 - originalSize;
    std::bitset<64> paddingBits(paddingLength);
    block <<= 8 * paddingLength;
    for (int i = 0; i < paddingLength; ++i)
    {
        block |= (paddingBits << (8 * i));
    }
}

int DES::removePaddingFromBitset(std::bitset<64>& block) const
{
    int paddingLength = block.to_ullong() & 0xFF;
    if (paddingLength > 0 && paddingLength <= 8)
    {
        block >>= 8 * paddingLength;
    }
    return paddingLength;
}

void DES::applyPermutationsOnChunks(
    const std::string& inputFile,
    const std::string& outputFile,
    std::vector<std::bitset<48>>& subKeys) const
{
    std::ifstream inputFileStream(inputFile, std::ios::binary);
    std::ofstream outputFileStream(outputFile, std::ios::binary);

    if (! inputFileStream.is_open() || ! outputFileStream.is_open())
    {
        std::cerr << "Error opening files\n";
        return;
    }

    char buffer[8];
    while (inputFileStream.read(buffer, 8) || inputFileStream.gcount() > 0)
    {
        int readBytes = inputFileStream.gcount();
        std::bitset<64> block = convertCharBufferToBitset(buffer, inputFileStream.gcount());

        if (inputFileStream.gcount() < 8)
        {
            addPaddingToBitset(block, inputFileStream.gcount());
            readBytes = 8;
        }

        std::bitset<64> encryptedBlock = applyPermutations(block, subKeys);

        if (operation == Operations::decrypt and inputFileStream.peek() == EOF)
        {
            readBytes = 8 - removePaddingFromBitset(encryptedBlock);
        }

        for (int i = readBytes - 1; i >= 0; --i)
        {
            outputFileStream.put(static_cast<char>((encryptedBlock >> (i * 8)).to_ulong()));
        }
    }

    inputFileStream.close();
    outputFileStream.close();
}

void DES::adjustKeySize(std::string& key) const
{
    if (key.size() > 8)
    {
        key = key.substr(0, 8);
        std::cout << "Key too long, using only the first 8 characters\n";
    }
    else
    {
        int i = 0;
        while (key.size() < 8)
        {
            key += key[i++];
        }
    }
}

void DES::encrypt(const std::string& inputFile, const std::string& outputFile, std::string password)
{
    adjustKeySize(password);
    std::bitset<64> keyBitset = keyStringToBitset(password);
    std::vector<std::bitset<48>> subKeys = generateKeys(keyBitset);

    applyPermutationsOnChunks(inputFile, outputFile, subKeys);
}

void DES::decrypt(const std::string& inputFile, const std::string& outputFile, std::string password)
{
    adjustKeySize(password);
    std::bitset<64> keyBitset = keyStringToBitset(password);
    std::vector<std::bitset<48>> subKeys = generateKeys(keyBitset);
    std::reverse(subKeys.begin(), subKeys.end());

    applyPermutationsOnChunks(inputFile, outputFile, subKeys);
}
} // namespace des
