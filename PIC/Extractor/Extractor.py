import pefile
import argparse


def handle_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extracts the .PIC section from a PE file"
    )
    parser.add_argument(
        "pefile", help="Path to the PE file to extract the .PIC section from"
    )
    parser.add_argument(
        "--section", help="Name of the section to extract", default="PIC"
    )
    return parser.parse_args()


def handle_bytes(data: bytes):
    data = [f"\\x{byte:02x}" for byte in data]
    data = "".join(data).rstrip("\\x00")
    print(data)


def main():
    args = handle_args()
    pe = pefile.PE(args.pefile)

    pic_section: pefile.SectionStructure = None
    for section in pe.sections:
        if args.section in section.Name.decode().rstrip("\x00"):
            pic_section = section
            break

    if pic_section is None:
        print(f"No {args.section} section found")
        return

    pic_section_data: bytes = pic_section.get_data()
    handle_bytes(pic_section_data)


if __name__ == "__main__":
    main()
