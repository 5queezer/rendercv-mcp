"""
RenderCV MCP Server — render CVs from YAML via claude.ai.

Deploy to Coolify:
  docker compose up -d

Then add as MCP connector in claude.ai:
  URL: https://cv.vasudev.xyz/mcp
"""

import base64
import pathlib
import tempfile

import fastmcp
from fastmcp.utilities.types import Image
from mcp_server import create_app

from rendercv.renderer.pdf_png import generate_pdf, generate_png
from rendercv.renderer.typst import generate_typst
from rendercv.schema.rendercv_model_builder import build_rendercv_dictionary_and_model

THEMES = [
    "classic",
    "ember",
    "engineeringclassic",
    "engineeringresumes",
    "harvard",
    "ink",
    "moderncv",
    "opal",
    "sb2nov",
]

EXAMPLE_DIR = pathlib.Path(__file__).parent / "examples"

mcp = fastmcp.FastMCP(
    "rendercv",
    instructions=(
        "Render professional CVs/resumes from YAML. "
        "Use render_cv(yaml) to generate a PDF and preview images. "
        "Use validate_cv(yaml) to check YAML for errors before rendering. "
        "Use list_themes() to see available themes. "
        "Use get_example(theme) to get a full example YAML for a given theme."
    ),
)


@mcp.tool()
def render_cv(yaml_content: str) -> list[Image | str]:
    """Render a CV from YAML content. Returns PNG page previews and the PDF as a base64-encoded download.

    Args:
        yaml_content: Full RenderCV YAML content (cv, design, locale, settings sections).
    """
    with tempfile.TemporaryDirectory(prefix="rendercv-mcp-") as tmp:
        tmp_path = pathlib.Path(tmp)
        output_folder = tmp_path / "output"
        output_folder.mkdir()

        _, model = build_rendercv_dictionary_and_model(
            yaml_content,
            output_folder=str(output_folder),
            dont_generate_html=True,
            dont_generate_markdown=True,
        )

        typst_path = generate_typst(model)
        if typst_path is None:
            return ["Error: Typst generation failed."]

        pdf_path = generate_pdf(model, typst_path)
        png_paths = generate_png(model, typst_path)

        results: list[Image | str] = []

        # PNG previews — claude.ai can display these inline
        if png_paths:
            for png_path in png_paths:
                png_bytes = png_path.read_bytes()
                results.append(Image(data=png_bytes, format="png"))

        # PDF as base64 download
        if pdf_path and pdf_path.exists():
            pdf_bytes = pdf_path.read_bytes()
            pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
            results.append(
                f"PDF ({len(pdf_bytes)} bytes, base64-encoded):\n"
                f"data:application/pdf;base64,{pdf_b64}"
            )

        if not results:
            return ["Error: No output generated."]

        return results


@mcp.tool()
def validate_cv(yaml_content: str) -> str:
    """Validate RenderCV YAML without rendering. Returns 'valid' or a list of errors.

    Args:
        yaml_content: Full RenderCV YAML content to validate.
    """
    try:
        build_rendercv_dictionary_and_model(yaml_content)
        return "valid"
    except Exception as e:
        return f"Validation failed:\n{e}"


@mcp.tool()
def list_themes() -> list[str]:
    """List all available built-in RenderCV themes."""
    return THEMES


@mcp.tool()
def get_example(theme: str = "classic") -> str:
    """Get a full example YAML file for a given theme.

    Args:
        theme: Theme name (classic, ember, engineeringclassic, engineeringresumes, harvard, ink, moderncv, opal, sb2nov).
    """
    theme = theme.lower().strip()
    if theme not in THEMES:
        return f"Unknown theme '{theme}'. Available: {', '.join(THEMES)}"

    # Find matching example file
    for example_file in sorted(EXAMPLE_DIR.glob("*.yaml")):
        if theme in example_file.stem.lower():
            return example_file.read_text(encoding="utf-8")

    return f"No example file found for theme '{theme}'."


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = create_app(
    mcp=mcp,
    title="RenderCV MCP",
)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
