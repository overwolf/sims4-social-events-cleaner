// SimsVirusCleaner.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <shlobj.h> // For SHGetFolderPath
#include <tchar.h>  // For _tcslen
#include <wincrypt.h>
#include <filesystem>
#include <tlhelp32.h>

#pragma comment(lib, "Crypt32.lib")

std::string updater_hash_ = "8c8558dc150de295f4b1d557243b5d978f09cfcec94145cd1ddb5315b3a0d92a";
std::string main_hash_ = "c98f0f5b89c6dac1482286faa2e33a84230c26ea38da4e013665582c9a04213b";

namespace fs = std::filesystem;

void RemoveFile(std::string filePath)
{
  if (std::remove(filePath.c_str()) == 0) {
    std::cout << "File deleted successfully " << filePath << std::endl;
  }
  else {
    perror("Error deleting file");
  }
}

bool CalculateFileHash(const std::string& filename, std::string& hash) {
  bool result = false;
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  BYTE rgbFile[1024];
  DWORD cbRead = 0;
  BYTE rgbHash[32]; // SHA-256 hash size is 32 bytes
  DWORD cbHash = 0;
  CHAR rgbDigits[] = "0123456789abcdef";
  HANDLE hFile = CreateFile(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

  if (hFile == INVALID_HANDLE_VALUE) {
    return false;
  }

  if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
      while (ReadFile(hFile, rgbFile, sizeof(rgbFile), &cbRead, NULL) && cbRead > 0) {
        CryptHashData(hHash, rgbFile, cbRead, 0);
      }
      cbHash = sizeof(rgbHash); // Use sizeof to determine the byte size of the hash buffer
      if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        hash.reserve(2 * cbHash);
        for (DWORD i = 0; i < cbHash; i++) {
          hash.append(1, rgbDigits[rgbHash[i] >> 4]);
          hash.append(1, rgbDigits[rgbHash[i] & 0xf]);
        }
        result = true;
      }
      CryptDestroyHash(hHash);
    }
    CryptReleaseContext(hProv, 0);
  }

  CloseHandle(hFile);
  return result;
}

void ScanFolder(std::string dir_path)
{
  for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
    if (entry.is_regular_file()) {
      std::string filePath = entry.path().string();
      std::string hash;
      if (CalculateFileHash(filePath, hash)) {
        if(hash == updater_hash_ ||
          hash == main_hash_)
        std::cout << "Found File: " << filePath << "\nSHA-256: " << hash << std::endl;
        RemoveFile(filePath);
      }
      else {
        std::cout << "Failed to calculate hash for file: " << filePath << std::endl;
      }
    }
  }
}

void KillProcessByName(std::string process_name) {
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
      do {
        std::string exe_file = pe32.szExeFile;
        if (exe_file == process_name) {
          HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
          if (hProcess != NULL) {
            TerminateProcess(hProcess, 1);
            CloseHandle(hProcess);
            std::cout << L"Terminated process virus: " << process_name << std::endl;
          }
        }
      } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
  }
}

void cleanTempFolder(const fs::path& tempPath) {
  try {
    for (const auto& entry : fs::directory_iterator(tempPath)) {
      try {
        fs::remove_all(entry.path());
        std::cout << "Removed: " << entry.path() << std::endl;
      }
      catch (const fs::filesystem_error& e) {
        std::cerr << "Error removing " << entry.path() << ": " << e.what() << std::endl;
      }
    }
  }
  catch (const std::exception& e) {
    std::cerr << "Error cleaning temp folder: " << e.what() << std::endl;
  }
}

void CleaningTemp()
{
  char* tempPathEnv = nullptr;
  size_t pathLen = 0;
  errno_t err = _dupenv_s(&tempPathEnv, &pathLen, "TEMP");

  if (err || tempPathEnv == nullptr) {
    std::cerr << "TEMP environment variable not found." << std::endl;
  }
  else {
    fs::path tempPath(tempPathEnv);
    std::cout << "Cleaning TEMP folder: " << tempPath << std::endl;
    cleanTempFolder(tempPath);
    free(tempPathEnv); // Don't forget to free the allocated memory
  }
}

int main()
{
  //Lets Kill the processes first//
  KillProcessByName("main.exe");
  KillProcessByName("main");
  KillProcessByName("Updater.exe");
  KillProcessByName("Updater");
  KillProcessByName("python.exe");
  KillProcessByName("python");
  /////////////////////////////////

  std::string prefix_path_one =
    "\\Microsoft\\Internet Explorer\\UserData\\";

  std::string prefix_path_two =
    "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\";

  // Initialize the path buffer
  CHAR appDataPath[MAX_PATH] = { 0 };

  // Retrieve the APPDATA folder path
  HRESULT result = SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, appDataPath);

  if (result != S_OK) {
    MessageBox(0, "Cannot clean because can't find roaming", "Title", 0);
    return 0;
  }

  std::string prefix_appdata = appDataPath;
  std::string first_path = prefix_appdata + prefix_path_one;
  std::string second_path = prefix_appdata + prefix_path_two;

  //printf("appDataPath: %s\n", first_path.c_str());
  ScanFolder(first_path);
  ScanFolder(second_path);
  CleaningTemp();
  system("PAUSE");
}