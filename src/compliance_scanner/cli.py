import typer

app = typer.Typer(
    name="compliance-scanner",
    help="CLI compliance automation for NIST 800-171 / CMMC 2.0 controls.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the installed version."""
    from compliance_scanner import __version__

    typer.echo(__version__)


if __name__ == "__main__":
    app()
