"""Generate Brainfuck code that outputs the RFC text."""

from pathlib import Path


def generate_brainfuck_for_text(text: str) -> str:
    """Generate Brainfuck code that outputs the given text.

    This uses a simple but effective algorithm:
    - For each character, calculate its ASCII value
    - Generate BF code to build that value on the current cell
    - Output the character with '.'
    - Move to next cell with '>'

    Args:
        text: The text to generate Brainfuck code for

    Returns:
        Brainfuck code as a string
    """
    bf_code: list[str] = []
    prev_value = 0

    for char in text:
        current_value = ord(char)
        diff = current_value - prev_value

        if diff > 0:
            # Need to add
            if diff <= 10:
                # Small difference, just add
                bf_code.append("+" * diff)
            else:
                # Large difference, use multiplication
                # Find a good factorization
                factor = int(diff**0.5)
                remainder = diff - (factor * factor)

                # Build up: factor * factor + remainder
                bf_code.append(">" + "+" * factor + "[<" + "+" * factor + ">-]<")
                if remainder > 0:
                    bf_code.append("+" * remainder)
                elif remainder < 0:
                    bf_code.append("-" * abs(remainder))
        elif diff < 0:
            # Need to subtract
            if abs(diff) <= 10:
                bf_code.append("-" * abs(diff))
            else:
                # Large negative difference
                factor = int(abs(diff) ** 0.5)
                remainder = abs(diff) - (factor * factor)

                bf_code.append(">" + "+" * factor + "[<" + "-" * factor + ">-]<")
                if remainder > 0:
                    bf_code.append("-" * remainder)
                elif remainder < 0:
                    bf_code.append("+" * abs(remainder))

        # Output the character
        bf_code.append(".")

        prev_value = current_value

    return "".join(bf_code)


def optimize_brainfuck(bf_code: str) -> str:
    """Apply basic optimizations to Brainfuck code.

    Args:
        bf_code: Raw Brainfuck code

    Returns:
        Optimized Brainfuck code
    """
    # Remove runs of +- and -+ that cancel out
    optimized = bf_code
    while "+-" in optimized or "-+" in optimized:
        optimized = optimized.replace("+-", "").replace("-+", "")

    return optimized


def generate_rfc_brainfuck(rfc_path: Path, output_path: Path) -> None:
    """Generate Brainfuck code that outputs the RFC.

    Args:
        rfc_path: Path to the RFC text file
        output_path: Path to write the Brainfuck code
    """
    print(f"Reading RFC from: {rfc_path}")
    rfc_text = rfc_path.read_text()

    print(f"Generating Brainfuck code for {len(rfc_text)} characters...")
    bf_code = generate_brainfuck_for_text(rfc_text)

    print("Optimizing Brainfuck code...")
    bf_code = optimize_brainfuck(bf_code)

    print(f"Writing {len(bf_code)} bytes of Brainfuck code to: {output_path}")
    output_path.write_text(bf_code)

    print("✓ Brainfuck code generated successfully!")
    print(f"  RFC size: {len(rfc_text)} characters")
    print(f"  BF code size: {len(bf_code)} characters")
    print(f"  Ratio: {len(bf_code) / len(rfc_text):.2f}x")


def main() -> None:
    """Main entry point."""
    project_root = Path(__file__).parent.parent
    rfc_path = project_root / "docs" / "rfc-ethernet-over-macca.txt"
    output_path = project_root / "docs" / "rfc-generator.bf"

    generate_rfc_brainfuck(rfc_path, output_path)


if __name__ == "__main__":
    main()
