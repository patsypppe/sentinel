from mcp.server.mcpserver import MCPServer

mcp = MCPServer("pysdk-demo")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


@mcp.tool()
def greet(name: str) -> str:
    return f"hi {name}"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        mcp.streamable_http_app(),
        host="127.0.0.1",
        port=int(__import__("os").environ.get("PORT", "3401")),
        log_level="warning",
    )
