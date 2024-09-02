#pragma once

#define PIC_SECTION_NAME "PIC"

#define PIC_START __pragma(code_seg(push, t1, PIC_SECTION_NAME))
#define PIC_END __pragma(code_seg(pop, t1))
#define PIC_DATA __declspec(allocate(PIC_SECTION_NAME))