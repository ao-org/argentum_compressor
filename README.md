# Argentum Compressor

This tool compresses asset folders (images, sounds, interfaces, maps, etc.) for use in the [Argentum Online](https://github.com/ao-org) ecosystem. It wraps custom compression logic with a simple CLI interface and is suitable for automation via Jenkins or other CI/CD systems.

---

## 🔧 Build

### Requirements

- Visual Studio 2022 Build Tools with C++ toolchain and Windows SDK
- MSVC v143 (Toolset)
- A working CMake or Visual Studio solution environment

Clone the repository and build with MSBuild:

```bash
git clone https://github.com/ao-org/argentum_compressor.git
cd argentum_compressor
msbuild argentum_compressor.sln /p:Configuration=Release /p:Platform=x86
```

> If using Jenkins, make sure `msbuild.exe` is correctly configured in Global Tool Configuration, or call `VsDevCmd.bat` before building.

---

## 🚀 Usage

### Command Syntax

```bash
argentum_compressor.exe compress -i <input_folder> -o <output_folder> -p <password>
```

**Parameters:**

- `-i`: Path to the folder containing uncompressed resources
- `-o`: Path where compressed files will be saved
- `-p`: Password used to encrypt or tag the resource files

**Example:**

```bash
argentum_compressor.exe compress -i "C:\Assets\Mapas" -o "C:\Assets\OUTPUT\Mapas" -p "12345-Password"
```

---

## 📂 Project Structure

The compressor CLI is implemented in [`argentum_compressor.cpp`](https://github.com/ao-org/argentum_compressor/blob/main/argentum_compressor.cpp). It:

- Parses command line arguments
- Validates input/output/password parameters
- Recursively processes all files in the input directory
- Compresses valid files and saves them to the output directory

---

## 📌 Notes

- Subfolders are supported and will be included recursively.
- Compression algorithm is internal to the compiled binary.
- Passwords are passed as plain text. Do not expose sensitive keys in public environments.

---

## ✅ License

This tool is part of the [Argentum Online Project](https://github.com/ao-org) and is open source.
Contributions are welcome.
