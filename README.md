# PIC

PIC/Shellocde generation template.

## [Generator](./PIC/Generator/)

The generator folder is main focus of this project. It contains the helpers for creating PIC as well as a "Hello, World!" message box example.

* [Helpers.h](./PIC/Generator/Helpers.h)/[c](./PIC/Generator/Helpers.c) - Contains helpers for generating PIC.
  * PIC_START - Denotes the start of a PIC section.
  * PIC_END - Denotes the end of a PIC section.
  * PIC_DATA - Denotes data, such as strings, for PIC code.
* [PIC.c](./PIC/Generator/PIC.c)/[h](./PIC/Generator/PIC.h) - PIC/Shellcode example.
* [Main.c](./PIC/Generator/Main.c) - Calls `PIC()` in `PIC.c`.

## [Extractor](./PIC/Extractor/)

Extracts the section and provides a byte string in a format which can be used by the provided runner.

Example result:
`\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20\xba\x08\x00\x00\x00\xe8\x7c\x00\x00\x00\x65\x48\x8b\x0c\x25\x60\x00\x00\x00\x48\x8b\xf8\x48\x8b\x51\x18\x48\x8b\x4a\x20\x48\x8b\x11\x48\x8b\x0a\x48\x8d\x15\x73\x01\x00\x00\x48\x8b\x59\x20\x48\x8b\xcb\xff\xd7\x48\x8d\x0d\x33\x01\x00\x00\xff\xd0\x48\x8d\x15\x4a\x01\x00\x00\x48\x8b\xc8\xff\xd7\x45\x33\xc9\x4c\x8d\x05\xfb\x00\x00\x00\x48\x8d\x15\xf4\x00\x00\x00\x33\xc9\xff\xd0\x48\x8d\x15\x19\x01\x00\x00\x48\x8b\xcb\xff\xd7\x33\xc9\x48\x8b\x5c\x24\x30\x48\x83\xc4\x20\x5f\x48\xff\xe0\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x48\x89\x5c\x24\x20\x57\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x45\x33\xd2\x48\x89\x74\x24\x20\x4c\x8b\xda\x48\x8b\x48\x18\x48\x8b\x41\x20\x48\x8b\x08\x48\x8b\x01\x48\x8b\x78\x20\x48\x63\x47\x3c\x8b\x9c\x38\x88\x00\x00\x00\x33\xc0\x48\x03\xdf\x8b\x73\x20\x48\x03\xf7\x44\x8b\x0e\x4c\x03\xcf\x48\x85\xd2\x74\x2d\x48\x89\x6c\x24\x18\x48\x8d\x2d\x7f\x00\x00\x00\x4c\x2b\xcd\x0f\x1f\x40\x00\x48\x8d\x0c\x28\x41\x0f\xb6\x14\x09\x3a\x11\x75\x23\x48\xff\xc0\x49\x3b\xc3\x72\xeb\x48\x8b\x6c\x24\x18\x8b\x43\x14\x48\x8b\x74\x24\x20\x4c\x3b\xd0\x75\x20\x33\xc0\x48\x8b\x5c\x24\x28\x5f\xc3\x8b\x43\x14\x4c\x3b\xd0\x73\xdd\x46\x8b\x4c\x96\x04\x49\xff\xc2\x4c\x03\xcf\x33\xc0\xeb\xb2\x8b\x4b\x24\x48\x03\xcf\x4a\x0f\xbf\x14\x51\x8b\x4b\x1c\x48\x8b\x5c\x24\x28\x48\x03\xcf\x48\x63\x04\x91\x48\x03\xc7\x5f\xc3\xcc\xcc\x48\x65\x6c\x6c\x6f\x2c\x20\x57\x6f\x72\x6c\x64\x21\x00\x00\x00\x47\x65\x74\x50\x72\x6f\x63\x41\x64\x64\x72\x65\x73\x73\x00\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x00\x00\x00\x00\x00\x45\x78\x69\x74\x50\x72\x6f\x63\x65\x73\x73\x00\x00\x00\x00\x00\x4d\x65\x73\x73\x61\x67\x65\x42\x6f\x78\x41\x00\x00\x00\x00\x00\x4c\x6f\x61\x64\x4c\x69\x62\x72\x61\x72\x79\x41`

## [Runner_Array](./PIC/Runner_Array/)

Simple runner which takes in bytes extracted by the extractor and runs them.

# Run Example

1. Open the Generator project.
2. Compile.
3. Extract the bytes with the Extractor.
4. Paste the bytes into `char shellcode[]` in [Runner_Array.cpp](./PIC/Runner_Array/Runner_Array.cpp).
5. Run the runner.