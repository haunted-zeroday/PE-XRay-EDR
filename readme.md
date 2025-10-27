# PE-XRay
**A lightweight, heuristic-based PE file analyzer for Windows**

![screenshot-dark](assets/screenshot.jpg)

---

## What is this?

**PE-XRay** is a tool for **static analysis of Windows executables (.exe, .dll)**.  
Instead of relying on traditional signature databases, it uses **heuristics** to identify anomalies, suspicious patterns, and structures commonly found in **malware, packers, and protectors**.

Think of it as a *“threat investigator”* rather than an antivirus —  
it shows you the **evidence**, and **you make the call**.

---

## Features

- **x86/x64 Support:** Works flawlessly with both 32-bit and 64-bit executables.  
- **Heuristic Engine:** Multi-layered scoring based on risk factors.  
- **Entropy Analysis:** Detects packed/encrypted code using overall and sliding-window entropy scanning.  
- **Import-Table Analysis:** Flags suspicious APIs (`CreateRemoteThread`, `SetWindowsHookExW`, etc.) and anomalous import tables.  
- **Structural Anomaly Detection:** Finds malformed PE headers, suspicious section flags (`Write+Execute`), and abnormal entry points.  
- **String Intelligence:** Scans for embedded strings (e.g. `cmd.exe`, `powershell`, URLs).  

---

## Tech Stack

| Component | Description |
|------------|-------------|
| **Language** | C (C11) |
| **Platform** | Windows (WinAPI) |
| **GUI** | IUP |
| **Compiler** | G++ (MinGW-w64) |

---

## How to Use

- **Launch PE-XRay.exe**

- **Click "Select file..." to select an .exe or .dll.**

- **Click "Analyze".**

Review the results:

Summary report: Final verdict, heuristic score, and detected anomalies.

Sections: Detailed view of PE sections with suspicious ones highlighted.

Imports: Tree view of all imported DLLs and functions (with risky ones marked).

## Building from Source

### Prerequisites

- **MSYS2** with `mingw-w64-x86_64-toolchain`  
- **IUP** and **CD** libraries

---

# Build Steps
## Build GUI version
```bash
make gui 
```

## Build CLI version
```bash
make cli
```

## Build all versions
```bash
make all
```