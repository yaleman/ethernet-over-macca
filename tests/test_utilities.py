"""Tests for EoMacca utility modules."""

from pathlib import Path


from src.brainfuck_generator import (
    generate_brainfuck_for_text,
    optimize_brainfuck,
)


class TestBrainfuckGenerator:
    """Test Brainfuck code generation."""

    def test_generate_simple_text(self) -> None:
        """Test generating BF code for simple text."""
        text = "Hi"
        bf_code = generate_brainfuck_for_text(text)

        # Should contain + for incrementing and . for output
        assert "+" in bf_code
        assert "." in bf_code
        # Should have 2 output commands (one for each character)
        assert bf_code.count(".") == 2

    def test_generate_empty_text(self) -> None:
        """Test generating BF code for empty string."""
        bf_code = generate_brainfuck_for_text("")
        # Empty string should produce no output
        assert bf_code == ""

    def test_generate_single_char(self) -> None:
        """Test single character generation."""
        bf_code = generate_brainfuck_for_text("A")
        assert "." in bf_code
        assert bf_code.count(".") == 1

    def test_optimize_brainfuck(self) -> None:
        """Test BF optimization."""
        # Test +- cancellation
        unoptimized = "+++.+-+-+-.---."
        optimized = optimize_brainfuck(unoptimized)

        # Should have fewer characters
        assert len(optimized) <= len(unoptimized)
        # Should still have output commands
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


class TestExamples:
    """Test example functions."""

    def test_examples_import(self) -> None:
        """Test that examples module can be imported."""
        from src import examples

        assert hasattr(examples, "example_basic_encapsulation")
        assert hasattr(examples, "example_efficiency_comparison")
        assert hasattr(examples, "example_visualize_layers")

    def test_example_basic_encapsulation(self) -> None:
        """Test basic encapsulation example runs without error."""
        from src.examples import example_basic_encapsulation

        # Should not raise any exceptions
        example_basic_encapsulation()

    def test_example_efficiency_comparison(self) -> None:
        """Test efficiency comparison example."""
        from src.examples import example_efficiency_comparison

        # Should not raise any exceptions
        example_efficiency_comparison()

    def test_example_visualize_layers(self) -> None:
        """Test layer visualization example."""
        from src.examples import example_visualize_layers

        # Should not raise any exceptions
        example_visualize_layers()


class TestPDFGenerator:
    """Test PDF generation utilities."""

    def test_pdf_generator_import(self) -> None:
        """Test PDF generator can be imported."""
        from src import pdf_generator

        assert hasattr(pdf_generator, "generate_brainfuck_pdf")

    def test_generate_brainfuck_pdf(self, tmp_path: Path) -> None:
        """Test PDF generation with small BF code."""
        from src.pdf_generator import generate_brainfuck_pdf

        # Create small BF file
        bf_file = tmp_path / "test.bf"
        bf_file.write_text("+++.>++.")

        output_file = tmp_path / "output.pdf"

        # Generate PDF
        generate_brainfuck_pdf(bf_file, output_file)

        # Verify PDF was created
        assert output_file.exists()
        assert output_file.stat().st_size > 0
