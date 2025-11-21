"""Generate a PDF containing the Brainfuck code."""

from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Flowable
from reportlab.lib.enums import TA_LEFT


def generate_brainfuck_pdf(bf_path: Path, output_path: Path) -> None:
    """Generate a PDF containing the Brainfuck code.

    Args:
        bf_path: Path to the Brainfuck code file
        output_path: Path to write the PDF
    """
    print(f"Reading Brainfuck code from: {bf_path}")
    bf_code = bf_path.read_text()

    print(f"Creating PDF at: {output_path}")

    # Create PDF document
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    # Build story (content)
    story: list[Flowable] = []

    # Styles
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading1"]

    # Create a monospace style for Brainfuck code
    bf_style = ParagraphStyle(
        "BrainfuckCode",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        alignment=TA_LEFT,
        leftIndent=0,
        rightIndent=0,
        wordWrap="CJK",  # Allow breaking at any character
    )

    # Title page
    story.append(Paragraph("EoMacca RFC Generator", title_style))
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            "Brainfuck Code for RFC 9999",
            heading_style,
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    # Info
    info_text = f"""
    This document contains Brainfuck code that, when executed by a Brainfuck
    interpreter, will output the complete text of RFC 9999: "A Standard for
    the Transmission of Ethernet Frames over IP over TCP over DNS over HTTP
    over TCP over IP over Ethernet (EoMacca)".
    <br/><br/>
    <b>Statistics:</b><br/>
    • Brainfuck code length: {len(bf_code):,} characters<br/>
    • Number of Brainfuck instructions:<br/>
    &nbsp;&nbsp;• '+' (increment): {bf_code.count("+"):,}<br/>
    &nbsp;&nbsp;• '-' (decrement): {bf_code.count("-"):,}<br/>
    &nbsp;&nbsp;• '.' (output): {bf_code.count("."):,}<br/>
    &nbsp;&nbsp;• '&lt;' (move left): {bf_code.count("<"):,}<br/>
    &nbsp;&nbsp;• '&gt;' (move right): {bf_code.count(">"):,}<br/>
    &nbsp;&nbsp;• '[' (loop start): {bf_code.count("["):,}<br/>
    &nbsp;&nbsp;• ']' (loop end): {bf_code.count("]"):,}<br/>
    <br/>
    To execute this code, copy it from the following pages and run it through
    a Brainfuck interpreter such as:<br/>
    • Online: https://copy.sh/brainfuck/<br/>
    • Python: bf (pip install bf)<br/>
    • Or any other Brainfuck interpreter of your choice<br/>
    """

    story.append(Paragraph(info_text, styles["Normal"]))
    story.append(PageBreak())

    # Add Brainfuck code
    story.append(Paragraph("Brainfuck Code", heading_style))
    story.append(Spacer(1, 0.1 * inch))

    # Split code into chunks for better formatting
    # We'll use 1000 character chunks
    chunk_size = 1000
    for i in range(0, len(bf_code), chunk_size):
        chunk = bf_code[i : i + chunk_size]
        # Escape special characters for XML
        chunk_escaped = (
            chunk.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )
        story.append(Paragraph(chunk_escaped, bf_style))

    # Build PDF
    print("Building PDF...")
    doc.build(story)

    print("✓ PDF generated successfully!")
    print(f"  Output: {output_path}")
    print(f"  Size: {output_path.stat().st_size:,} bytes")


def main() -> None:
    """Main entry point."""
    project_root = Path(__file__).parent.parent
    bf_path = project_root / "docs" / "rfc-generator.bf"
    output_path = project_root / "brainfuck_rfc.pdf"

    if not bf_path.exists():
        print(f"Error: Brainfuck code not found at {bf_path}")
        print("Run brainfuck_generator.py first!")
        return

    generate_brainfuck_pdf(bf_path, output_path)


if __name__ == "__main__":
    main()
