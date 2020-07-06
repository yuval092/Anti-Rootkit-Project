// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"
#include <iostream>
#include <tchar.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <fstream>
#include <map>

#define LIST_SIZE 1024
#define IOCTL_SCAN_HOOKS 1
#define IOCTL_ADD_NEW_PROCESS 2
#define DRIVER_NAME "DetectionDriver"
#define DRIVER_START "sc start DetectionDriver"
#define DRIVER_SYMBOL_NAME "\\\\.\\DetectionDriver"
#define DRIVER_PATH "%SystemRoot%\\System32\\DetectionDriver.sys"
#define SCAN_RESULT_FILE_PATH "%SystemRoot%\\System32\\ScanResult.txt"
#define DRIVER_REGISTER "sc create DetectionDriver binpath= %SystemRoot%\\system32\\drivers\\DetectionDriver.sys type= kernel start= demand"

#endif //PCH_H
