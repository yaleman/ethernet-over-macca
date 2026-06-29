"""Tests for EoMacca utility modules."""

from pathlib import Path

from src import examples
from src.brainfuck_generator import (
    generate_brainfuck_for_text,
    optimize_brainfuck,
)
from src.pdf_generator import generate_brainfuck_pdf
from src.examples import example_basic_encapsulation
from src.examples import example_efficiency_comparison
from src.examples import example_visualize_layers


class TestBrainfuckGenerator:
    """Test Brainfuck code generation."""

    def test_generate_simple_text(self) -> None:
        """Test generating BF code for simple text."""
        text = "Hi"
        bf_code = generate_brainfuck_for_text(text)

        assert "+" in bf_code
        assert "." in bf_code
        assert bf_code.count(".") == 2

    def test_generate_empty_text(self) -> None:
        """Test generating BF code for empty string."""
        bf_code = generate_brainfuck_for_text("")
        assert bf_code == ""

    def test_generate_single_char(self) -> None:
        """Test single character generation."""
        bf_code = generate_brainfuck_for_text("A")
        assert "." in bf_code
        assert bf_code.count(".") == 1

    def test_generate_large_jump(self) -> None:
        """Test generation with large character value differences."""
        text = " A"
        bf_code = generate_brainfuck_for_text(text)
        assert bf_code.count(".") == 2

    def test_generate_descending_chars(self) -> None:
        """Test generation with descending character values."""
        text = "CBA"
        bf_code = generate_brainfuck_for_text(text)
        assert bf_code.count(".") == 3

    def test_optimize_brainfuck(self) -> None:
        """Test BF optimization."""
        unoptimized = "+++.+-+-+-.---."
        optimized = optimize_brainfuck(unoptimized)

        assert len(optimized) <= len(unoptimized)
        assert optimized.count(".") == 3

    def test_optimize_no_change(self) -> None:
        """Test optimization when no changes needed."""
        code = "+++..."
        optimized = optimize_brainfuck(code)
        assert optimized == code

    def test_optimize_complete_cancellation(self) -> None:
        """Test complete cancellation of operations."""
        code = "+-+-+-"
        optimized = optimize_brainfuck(code)
        assert optimized == ""

    def test_optimize_mixed_code(self) -> None:
        """Test optimization preserves non-canceling operations."""
        code = "+++>++<-."
        optimized = optimize_brainfuck(code)
        assert optimized == code


class TestExamples:
    """Test example functions."""

    def test_examples_import(self) -> None:
        """Test that examples module can be imported."""

        assert hasattr(examples, "example_basic_encapsulation")
        assert hasattr(examples, "example_efficiency_comparison")
        assert hasattr(examples, "example_visualize_layers")

    def test_example_basic_encapsulation(self) -> None:
        """Test basic encapsulation example runs without error."""

        example_basic_encapsulation()

    def test_example_efficiency_comparison(self) -> None:
        """Test efficiency comparison example."""

        example_efficiency_comparison()

    def test_example_visualize_layers(self) -> None:
        """Test layer visualization example."""

        example_visualize_layers()


class TestPDFGenerator:
    """Test PDF generation utilities."""

    def test_generate_brainfuck_pdf(self, tmp_path: Path) -> None:
        """Test PDF generation with small BF code."""
        bf_file = tmp_path / "test.bf"
        bf_file.write_text("+++.>++.")

        output_file = tmp_path / "output.pdf"

        generate_brainfuck_pdf(bf_file, output_file)

        assert output_file.exists()
        assert output_file.stat().st_size > 0

    def test_generate_brainfuck_pdf_empty(self, tmp_path: Path) -> None:
        """Test PDF generation with empty BF code."""

        bf_file = tmp_path / "empty.bf"
        bf_file.write_text("")

        output_file = tmp_path / "output_empty.pdf"

        generate_brainfuck_pdf(bf_file, output_file)

        assert output_file.exists()
        assert output_file.stat().st_size > 0
