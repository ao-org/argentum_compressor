/*
    Argentum Online Compressor tool

    Copyright (C) 2025 Noland Studios LTD

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

 */
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cctype>
#include <iterator>

// Include the CryptoSys API header.
#include "diCryptoSys.h"

namespace fs = std::filesystem;

//--------------------------------------------------------------------------
// Archive header structures (matching VB6 binary layout)
//--------------------------------------------------------------------------
constexpr size_t FILEHEADER_SIZE = 38;  // 4 + 2 + 32 bytes
constexpr size_t INFOHEADER_SIZE = 44;  // 4 + 4 + 32 + 4 bytes

const std::string fixedKeyHex = "AB45456789ABCDEFA0E1D2C3B4A59666";
const std::string fixedIVHex = "FEDCAA9A76543A10FEDCBA9876543322";

#pragma pack(push, 1)
struct FileHeader {
    uint32_t fileSize;       // Total archive size (bytes)
    uint16_t numFiles;       // Number of files contained
    char passwordHash[32];   // MD5 hash (32 hex characters) of the password
};

struct InfoHeader {
    uint32_t fileStart;        // Offset where file data begins
    uint32_t fileSize;         // Size of the compressed+encrypted blob
    char fileName[32];         // Filename (lowercase, padded to 32 bytes)
    uint32_t uncompressedSize; // Original uncompressed file size
};
#pragma pack(pop)

struct FileEntry {
    std::string relativePath;         // Relative path (only base filename stored)
    std::vector<unsigned char> data;  // Final encrypted data blob
    uint32_t uncompressedSize;
};

//--------------------------------------------------------------------------
// Helper Functions
//--------------------------------------------------------------------------

// Convert a hex string to a vector of bytes.
std::vector<unsigned char> hexStringToBytesLocal(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Convert a string to lowercase.
std::string toLowerStr(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Print a simple progress bar.
void printProgressBar(double progress) {
    const int barWidth = 50;
    std::cout << "\r[";
    int pos = static_cast<int>(barWidth * progress);
    for (int i = 0; i < barWidth; ++i)
        std::cout << (i < pos ? "#" : "-");
    std::cout << "] " << int(progress * 100.0) << " %";
    std::cout.flush();
}

// Print a buffer as a comma-separated hex array.
void printHexBuffer(const std::string& label, const std::vector<unsigned char>& buf) {
    std::cout << label << " (" << buf.size() << " bytes):\n";
    std::cout << "  [ ";
    for (size_t i = 0; i < buf.size(); ++i) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(buf[i]);
        if (i != buf.size() - 1)
            std::cout << ", ";
    }
    std::cout << " ]" << std::dec << "\n";
}

//--------------------------------------------------------------------------
// CryptoSys API Compression Wrappers using diCryptoSys.h
//--------------------------------------------------------------------------

// csCompress: Compress data using ZLIB_Deflate.
// After compression, ensure that the standard two-byte header (0x78, 0x9C) is present.
std::vector<unsigned char> csCompress(const std::vector<unsigned char>& data) {
    long outSize = static_cast<long>(data.size() * 2); // Estimate output size.
    std::vector<unsigned char> out(outSize);
    long ret = ZLIB_Deflate(out.data(), outSize, data.data(), static_cast<long>(data.size()));
    if (ret < 0) {
        throw std::runtime_error("ZLIB_Deflate failed with code " + std::to_string(ret));
    }
    out.resize(ret);
    // Check for standard header (0x78, 0x9C) and prepend if missing.
    if (out.size() < 2 || out[0] != 0x78 || out[1] != 0x9C) {
        std::vector<unsigned char> newOut;
        newOut.push_back(0x78);
        newOut.push_back(0x9C);
        newOut.insert(newOut.end(), out.begin(), out.end());
        out = newOut;
    }
    return out;
}

// csDecompress: Decompress data using ZLIB_Inflate.
// uncompressedSize must be provided.
std::vector<unsigned char> csDecompress(const std::vector<unsigned char>& data, size_t uncompressedSize) {
    long nOut = static_cast<long>(uncompressedSize);
    std::vector<unsigned char> out(nOut);
    long ret = ZLIB_Inflate(out.data(), nOut, data.data(), static_cast<long>(data.size()));
    if (ret < 0) {
        throw std::runtime_error("ZLIB_Inflate failed with code " + std::to_string(ret));
    }
    out.resize(ret);
    return out;
}

//--------------------------------------------------------------------------
// CryptoSys API Wrappers for Encryption/Decryption and MD5
//--------------------------------------------------------------------------

// csEncrypt: Encrypt data using AES-128/CFB/nopad mode via CIPHER_EncryptBytes2.
std::vector<unsigned char> csEncrypt(const std::vector<unsigned char>& data,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {
    long outSize = static_cast<long>(data.size());
    std::vector<unsigned char> out(outSize);
    long ret = CIPHER_EncryptBytes2(out.data(), outSize, data.data(), static_cast<long>(data.size()),
        key.data(), static_cast<long>(key.size()),
        iv.data(), static_cast<long>(iv.size()),
        "aes128/cfb/nopad", 0);
    if (ret < 0) {
        throw std::runtime_error("CIPHER_EncryptBytes2 failed with code " + std::to_string(ret));
    }
    out.resize(ret);
    return out;
}

// csDecrypt: Decrypt data using AES-128/CFB/nopad mode via CIPHER_DecryptBytes2.
std::vector<unsigned char> csDecrypt(const std::vector<unsigned char>& data,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {
    long outSize = static_cast<long>(data.size());
    std::vector<unsigned char> out(outSize);
    long ret = CIPHER_DecryptBytes2(out.data(), outSize, data.data(), static_cast<long>(data.size()),
        key.data(), static_cast<long>(key.size()),
        iv.data(), static_cast<long>(iv.size()),
        "aes128/cfb/nopad", 0);
    if (ret < 0) {
        throw std::runtime_error("CIPHER_DecryptBytes2 failed with code " + std::to_string(ret));
    }
    out.resize(ret);
    return out;
}

// csMD5String: Compute MD5 hash using MD5_StringHexHash.
std::string csMD5String(const std::string& input) {
    char digest[API_MD5_CHARS + 1] = { 0 };  // API_MD5_CHARS is 32.
    long ret = MD5_StringHexHash(digest, input.c_str());
    if (ret < 0) {
        throw std::runtime_error("MD5_StringHexHash failed with code " + std::to_string(ret));
    }
    return std::string(digest);
}

//--------------------------------------------------------------------------
// doCryptData: XOR encryption/decryption (symmetric), equivalent to VB6 DoCrypt_Data.
void doCryptData(std::vector<unsigned char>& data, const std::string& password) {
    std::string pwd = password.empty() ? "Contraseña" : password;
    int passLen = static_cast<int>(pwd.size());
    if (data.empty() || passLen == 0)
        return;
    int c_index = ((data.size() - 1) % passLen);
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= static_cast<unsigned char>(pwd[c_index]);
        c_index--;
        if (c_index < 0)
            c_index = passLen - 1;
    }
}

//--------------------------------------------------------------------------
// compressFiles: For each file in inputDir, read its data, and if non-empty, process it.
// Pipeline:
//   1. Compress using csCompress (ZLIB_Deflate)
//   2. Encrypt using csEncrypt (AES-128/CFB/nopad via CIPHER_EncryptBytes2)
//   3. XOR-encrypt with the provided password
// The archive is then written with a FileHeader and one InfoHeader per file.
// If verbose is true, the tool prints intermediate buffers.
bool compressFiles(const fs::path& inputDir, const fs::path& outputFile, const std::string& password, bool verbose) {
    std::vector<FileEntry> entries;

    // Count files.
    size_t totalFiles = 0;
    for (auto& p : fs::recursive_directory_iterator(inputDir))
        if (fs::is_regular_file(p.path()))
            totalFiles++;
    if (totalFiles == 0) {
        std::cerr << "No files found in " << inputDir << "\n";
        return false;
    }

    size_t currentIndex = 0;
    for (auto& p : fs::recursive_directory_iterator(inputDir)) {
        if (fs::is_regular_file(p.path())) {
            currentIndex++;
            std::cout << "\n[" << currentIndex << "/" << totalFiles << "] Processing file: "
                << p.path().filename().string() << "\n";
            std::ifstream ifs(p.path(), std::ios::binary);
            if (!ifs) {
                std::cerr << "Failed to open file " << p.path() << "\n";
                continue;
            }
            std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(ifs)),
                std::istreambuf_iterator<char>());
            // Skip empty files.
            if (fileData.empty()) {
                std::cout << "Skipping empty file: " << p.path().filename().string() << "\n";
                continue;
            }
            if (verbose) {
                std::cout << "Original Data:" << std::endl;
                // Print only first 128 bytes if too large.
                std::vector<unsigned char> preview(fileData.begin(), fileData.begin() + std::min<size_t>(fileData.size(), 128));
                // Print as hex:
                std::cout << "[ ";
                for (unsigned char b : preview) {
                    std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<int>(b) << " ";
                }
                std::cout << "]" << std::dec << "\n";
            }
            FileEntry fe;
            fe.relativePath = fs::relative(p.path(), inputDir).generic_string();
            fe.uncompressedSize = static_cast<uint32_t>(fileData.size());

            // Compress using CryptoSys API's ZLIB_Deflate.
            std::vector<unsigned char> compressed = csCompress(fileData);
            if (verbose) {
                printHexBuffer("Compressed Data", compressed);
            }
            // Prepare key and IV.
            std::vector<unsigned char> key = hexStringToBytesLocal(fixedKeyHex);
            std::vector<unsigned char> iv = hexStringToBytesLocal(fixedIVHex);
            // Encrypt using CryptoSys API (AES-128/CFB/nopad via CIPHER_EncryptBytes2).
            std::vector<unsigned char> encrypted = csEncrypt(compressed, key, iv);
            if (verbose) {
                printHexBuffer("Encrypted Data", encrypted);
            }
            // XOR-encrypt with the provided password.
            doCryptData(encrypted, password);
            if (verbose) {
                printHexBuffer("XOR-Encrypted Data", encrypted);
            }
            fe.data = std::move(encrypted);
            entries.push_back(std::move(fe));

            printProgressBar(static_cast<double>(currentIndex) / totalFiles);
        }
    }
    std::cout << "\nAll files processed. Sorting and writing archive...\n";

    // Sort entries by base filename (case-insensitive).
    std::sort(entries.begin(), entries.end(), [](const FileEntry& a, const FileEntry& b) {
        std::string nameA = toLowerStr(fs::path(a.relativePath).filename().string());
        std::string nameB = toLowerStr(fs::path(b.relativePath).filename().string());
        return nameA < nameB;
        });

    uint16_t numFiles = static_cast<uint16_t>(entries.size());
    // Calculate header size (no extra byte added here)
    size_t headerSize = FILEHEADER_SIZE + numFiles * INFOHEADER_SIZE;

    // Set currentOffset to headerSize + 1 so that stored offsets are 1-based
    uint32_t currentOffset = static_cast<uint32_t>(headerSize) + 1;
    uint32_t totalSize = static_cast<uint32_t>(headerSize) + 1;
    for (auto& e : entries)
        totalSize += static_cast<uint32_t>(e.data.size());

   
    FileHeader fh;
    fh.fileSize = totalSize;
    fh.numFiles = numFiles;
    std::string pwdHash = csMD5String(password.empty() ? "Contraseña" : password);
    std::memset(fh.passwordHash, ' ', sizeof(fh.passwordHash));
    std::memcpy(fh.passwordHash, pwdHash.data(), std::min(pwdHash.size(), sizeof(fh.passwordHash)));

    std::ofstream ofs(outputFile, std::ios::binary);
    if (!ofs) {
        std::cerr << "Failed to open output file: " << outputFile << "\n";
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(&fh), sizeof(fh));

    std::vector<InfoHeader> infoHeaders;
    for (auto& e : entries) {
        InfoHeader ih;
        ih.fileStart = currentOffset;
        ih.fileSize = static_cast<uint32_t>(e.data.size());
        ih.uncompressedSize = e.uncompressedSize;
        fs::path p(e.relativePath);
        std::string filename = toLowerStr(p.filename().string());
        if (filename.size() > 32)
            filename = filename.substr(0, 32);
        else if (filename.size() < 32)
            filename.append(32 - filename.size(), ' ');
        std::memcpy(ih.fileName, filename.data(), 32);
        infoHeaders.push_back(ih);
        currentOffset += ih.fileSize;
    }
    for (auto& ih : infoHeaders)
        ofs.write(reinterpret_cast<const char*>(&ih), sizeof(ih));
    for (auto& e : entries)
        ofs.write(reinterpret_cast<const char*>(e.data.data()), e.data.size());
    ofs.close();
    std::cout << "\nArchive successfully written to " << outputFile << "\n";
    return true;
}

//--------------------------------------------------------------------------
// extractFiles: Opens an archive, verifies the header, then for each file:
// 1. Reads the encrypted blob.
// 2. XOR-decrypts it.
// 3. Decrypts using CryptoSys API (AES-128/CFB/nopad via CIPHER_DecryptBytes2).
// 4. Decompresses using ZLIB_Inflate.
// 5. Writes the resulting file.
bool extractFiles(const fs::path& archiveFile, const fs::path& outputDir, const std::string& password) {
    std::ifstream ifs(archiveFile, std::ios::binary);
    if (!ifs) {
        std::cerr << "Failed to open archive file: " << archiveFile << "\n";
        return false;
    }
    ifs.seekg(0, std::ios::end);
    uint32_t archiveSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    FileHeader fh;
    ifs.read(reinterpret_cast<char*>(&fh), sizeof(fh));
    if (archiveSize != fh.fileSize) {
        std::cerr << "Archive file size mismatch. File may be corrupted.\n";
        return false;
    }
    std::string providedHash = csMD5String(password.empty() ? "Contraseña" : password);
    std::string storedHash(fh.passwordHash, sizeof(fh.passwordHash));
    storedHash.erase(std::find(storedHash.begin(), storedHash.end(), ' '), storedHash.end());
    if (providedHash != storedHash) {
        std::cerr << "Invalid password.\n";
        return false;
    }
    uint16_t numFiles = fh.numFiles;
    std::vector<InfoHeader> infoHeaders(numFiles);
    for (int i = 0; i < numFiles; i++)
        ifs.read(reinterpret_cast<char*>(&infoHeaders[i]), sizeof(InfoHeader));
    fs::create_directories(outputDir);

    std::cout << "Extracting " << numFiles << " files...\n";
    std::vector<unsigned char> key = hexStringToBytesLocal(fixedKeyHex);
    std::vector<unsigned char> iv = hexStringToBytesLocal(fixedIVHex);
    for (int i = 0; i < numFiles; i++) {
        InfoHeader& ih = infoHeaders[i];
        ifs.seekg(ih.fileStart, std::ios::beg);
        std::vector<unsigned char> encryptedData(ih.fileSize);
        ifs.read(reinterpret_cast<char*>(encryptedData.data()), ih.fileSize);
        // XOR-decrypt.
        doCryptData(encryptedData, password);
        // AES-decrypt using CryptoSys API.
        std::vector<unsigned char> aesDecrypted = csDecrypt(encryptedData, key, iv);
        // Decompress using ZLIB_Inflate.
        std::vector<unsigned char> decompressed = csDecompress(aesDecrypted, ih.uncompressedSize);
        std::string filename(ih.fileName, sizeof(ih.fileName));
        filename.erase(std::find_if(filename.rbegin(), filename.rend(),
            [](unsigned char ch) { return !std::isspace(ch); }).base(),
            filename.end());
        fs::path outPath = outputDir / filename;
        std::ofstream ofs(outPath, std::ios::binary);
        if (!ofs) {
            std::cerr << "Failed to write file: " << outPath << "\n";
            continue;
        }
        ofs.write(reinterpret_cast<const char*>(decompressed.data()), decompressed.size());
        ofs.close();
        std::cout << "[" << (i + 1) << "/" << numFiles << "] Extracted: " << filename << "\n";
    }
    return true;
}

//--------------------------------------------------------------------------
// dumpHeaders: Dumps the FileHeader and InfoHeaders from an archive for debugging.
bool dumpHeaders(const fs::path& archiveFile) {
    std::ifstream ifs(archiveFile, std::ios::binary);
    if (!ifs) {
        std::cerr << "Failed to open archive file: " << archiveFile << "\n";
        return false;
    }
    FileHeader fh;
    ifs.read(reinterpret_cast<char*>(&fh), sizeof(fh));
    std::cout << "File Header:" << std::endl;
    std::cout << "  File Size: " << fh.fileSize << std::endl;
    std::cout << "  Number of Files: " << fh.numFiles << std::endl;
    std::string pwdHash(fh.passwordHash, sizeof(fh.passwordHash));
    std::cout << "  Password Hash: [" << pwdHash << "]" << std::endl;

    uint16_t numFiles = fh.numFiles;
    std::vector<InfoHeader> infoHeaders(numFiles);
    for (int i = 0; i < numFiles; i++)
        ifs.read(reinterpret_cast<char*>(&infoHeaders[i]), sizeof(InfoHeader));
    std::cout << "\nInfo Headers:" << std::endl;
    for (int i = 0; i < numFiles; i++) {
        std::string fileName(infoHeaders[i].fileName, sizeof(infoHeaders[i].fileName));
        fileName.erase(std::find_if(fileName.rbegin(), fileName.rend(),
            [](unsigned char ch) { return !std::isspace(ch); }).base(),
            fileName.end());
        std::cout << "File " << (i + 1) << ": " << fileName << std::endl;
        std::cout << "  File Start: " << infoHeaders[i].fileStart << std::endl;
        std::cout << "  Compressed File Size: " << infoHeaders[i].fileSize << std::endl;
        std::cout << "  Uncompressed Size: " << infoHeaders[i].uncompressedSize << std::endl;
    }
    return true;
}

//--------------------------------------------------------------------------
// Main: Command-line interface for modes: compress, extract, dump.
// Verbose mode is enabled with -v.
int main(int argc, char* argv[]) {
    std::cout << "Argentum Compressor Tool for Argentum Online\n";
    std::cout << "Copyright (C) 2025 Noland Studios LTD. All rights reserved.\n\n";

    if (argc < 3) {
        std::cerr << "Usage:\n"
            << "  " << argv[0] << " compress -i <input_dir> -o <archive_file> -p <password> [-v]\n"
            << "  " << argv[0] << " extract  -i <archive_file> -o <output_dir> -p <password>\n"
            << "  " << argv[0] << " dump     -i <archive_file>\n";
        return 1;
    }

    std::string mode = argv[1];
    fs::path input, output;
    std::string password;
    bool verbose = false;

    // Parse command line arguments.
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            input = argv[++i];
        }
        else if (arg == "-o" && i + 1 < argc) {
            output = argv[++i];
        }
        else if (arg == "-p" && i + 1 < argc) {
            password = argv[++i];
        }
        else if (arg == "-v") {
            verbose = true;
        }
    }

    if (mode == "dump") {
        if (input.empty()) {
            std::cerr << "Error: Please specify the archive file using -i\n";
            return 1;
        }
        return dumpHeaders(input) ? 0 : 1;
    }
    else if (mode == "compress") {
        if (input.empty() || output.empty() || password.empty()) {
            std::cerr << "Error: For compress mode, -i, -o, and -p are required.\n";
            return 1;
        }
        return compressFiles(input, output, password, verbose) ? 0 : 1;
    }
    else if (mode == "extract") {
        if (input.empty() || output.empty() || password.empty()) {
            std::cerr << "Error: For extract mode, -i, -o, and -p are required.\n";
            return 1;
        }
        return extractFiles(input, output, password) ? 0 : 1;
    }
    else {
        std::cerr << "Unknown mode: " << mode << "\n";
        return 1;
    }
}
