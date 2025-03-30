from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import PageRightsConfiguration
from fastmcp import FastMCP

mcp = FastMCP("github.com/CaptainNox/x64dbg-mcp")
dbgClient = X64DbgClient("C:\\x64dbg\\release\\x64\\x64dbg.exe")

@mcp.tool()
def start_session(target: str) -> int:
    """
    Start a debugging session with a target executable and run until the entrypoint.

    Args:
        target (str): Path to the executable to launch.

    Returns:
        int: Session ID of the debugging session.
    """
    if target == "":
        return -1
    
    session_id = dbgClient.start_session(target)
    dbgClient.go()

    return session_id

@mcp.tool()
def start_session_attach(pid: int) -> int:
    """
    Attach to a running process and create a debugging session.

    Args:
        pid (int): Process ID of the target process to attach to.

    Returns:
        int: Session ID of the debugging session.
    """
    return dbgClient.start_session_attach(pid)

@mcp.tool()
def continue_execution() -> None:
    """
    Continue execution until the debuggee is halted.

    Args:
        None

    Returns:
        None
    """
    dbgClient.go()

@mcp.tool()
def detach_session() -> None:
    """
    Detach from the current debug session.

    Args:
        None

    Returns:
        None
    """
    dbgClient.detach_session()

@mcp.tool()
def pause() -> bool:
    """
    Pause the debuggee. This method will block until the debuggee is in the stopped state.

    Args:
        None

    Returns:
        bool: True if the debuggee was successfully paused, False otherwise.
    """
    return dbgClient.pause()

@mcp.tool()
def stepi(
    step_count: int = 1, 
    pass_exceptions: bool = False, 
    swallow_exceptions: bool = False, 
    wait_for_ready: bool = True,
    wait_timeout: int = 2) -> bool:
    """
    Step into the next instruction. This method will block until the debuggee is in the stopped state.

    Args:
        step_count (int): Number of instructions to step into. Default is 1.
        pass_exceptions (bool): Whether to pass exceptions during stepping. Default is False.
        swallow_exceptions (bool): Whether to swallow exceptions during stepping. Default is False.
        wait_for_ready (bool): Whether to wait for the debuggee to be ready. Default is True.
        wait_timeout (int): Timeout in seconds to wait for the debuggee to be ready. Default is 2.

    Returns:
        bool: True if the step was successful, False otherwise.
    """
    return dbgClient.stepi(
        step_count=step_count, 
        pass_exceptions=pass_exceptions, 
        swallow_exceptions=swallow_exceptions, 
        wait_for_ready=wait_for_ready,
        wait_timeout=wait_timeout
    )

@mcp.tool()
def stepo(
    step_count: int = 1, 
    pass_exceptions: bool = False, 
    swallow_exceptions: bool = False, 
    wait_for_ready: bool = True,
    wait_timeout: int = 2) -> bool:
    """
    Step out of the current function. This method will block until the debuggee is in the stopped state.

    Args:
        step_count (int): Number of instructions to step out. Default is 1.
        pass_exceptions (bool): Whether to pass exceptions during stepping. Default is False.
        swallow_exceptions (bool): Whether to swallow exceptions during stepping. Default is False.
        wait_for_ready (bool): Whether to wait for the debuggee to be ready. Default is True.
        wait_timeout (int): Timeout in seconds to wait for the debuggee to be ready. Default is 2.

    Returns:
        bool: True if the step was successful, False otherwise.
    """
    return dbgClient.stepo(
        step_count=step_count, 
        pass_exceptions=pass_exceptions, 
        swallow_exceptions=swallow_exceptions, 
        wait_for_ready=wait_for_ready,
        wait_timeout=wait_timeout
    )

@mcp.tool()
def skip(skip_count: int = 1, wait_for_ready: bool = True, wait_timeout: int = 2) -> bool:
    """
    Skip over N instructions.

    Args:
        skip_count (int): Number of instructions to skip. Default is 1.
        wait_for_ready (bool): Whether to wait for the debuggee to be ready. Default is True.
        wait_timeout (int): Timeout in seconds to wait for the debuggee to be ready. Default is 2.

    Returns:
        bool: True if the skip was successful, False otherwise.
    """
    return dbgClient.skip(
        skip_count=skip_count, 
        wait_for_ready=wait_for_ready,
        wait_timeout=wait_timeout
    )

@mcp.tool()
def ret(frames: int = 1, wait_timeout: int = 2) -> bool:
    """
    Step until a return instruction is encountered.

    Args:
        frames (int): Number of stack frames to return from. Default is 1.
        wait_timeout (int): Timeout in seconds to wait for the debuggee to be ready. Default is 2.

    Returns:
        bool: True if the return was successful, False otherwise.
    """
    return dbgClient.ret(
        frames=frames, 
        wait_timeout=wait_timeout
    )

@mcp.tool()
def write_memory(addr: int, data: bytes) -> bool:
    """
    Write data to the debuggee's memory at the specified address.

    Args:
        addr (int): Address in the debuggee's memory to write to.
        data (bytes): Data to write to the specified address.

    Returns:
        bool: True if the memory write was successful, False otherwise.
    """
    return dbgClient.write_memory(addr, data)

@mcp.tool()
def read_memory(addr: int, size: int) -> bytes:
    """
    Read data from the debuggee's memory at the specified address.

    Args:
        addr (int): Address in the debuggee's memory to read from.
        size (int): Number of bytes to read.

    Returns:
        bytes: Data read from the specified address.
    """
    return dbgClient.read_memory(addr, size)

@mcp.tool()
def read_word(addr: int) -> int:
    """
    Read a word (4 bytes) from the debuggee's memory at the specified address.

    Args:
        addr (int): Address in the debuggee's memory to read from.

    Returns:
        int: Word read from the specified address.
    """
    return dbgClient.read_word(addr)

@mcp.tool()
def read_dword(addr: int) -> int:
    """
    Read a DWORD from the debuggee's memory at the specified address.

    Args:
        addr (int): Address in the debuggee's memory to read from.

    Returns:
        int: DWORD read from the specified address.
    """
    return dbgClient.read_dwword(addr)

@mcp.tool()
def read_qword(addr: int) -> int:
    """
    Read a QWORD from the debuggee's memory at the specified address.

    Args:
        addr (int): Address in the debuggee's memory to read from.

    Returns:
        int: QWORD read from the specified address.
    """
    return dbgClient.read_qword(addr)

@mcp.tool()
def virt_alloc(size: int = 4096, addr: int = 0) -> int:
    """
    Allocate memory in the debuggee's address space.

    Args:
        size (int): Size of memory to allocate in bytes. Default is 4096.
        addr (int): Address to allocate memory at. Default is 0 (system chooses the address).

    Returns:
        int: Address of the allocated memory.
    """
    return dbgClient.virt_alloc(size, addr)

@mcp.tool()
def virt_protect(addr: int, page_rights: str) -> bool:
    """
    Change the protection of a page in the debuggee's memory.

    Args:
        addr (int): Address of the page to change protection.
        page_rights (str): New protection rights for the page. 
            The proections are: Execute, ExecuteRead, ExecuteReadWrite, ExecuteReadWriteCopy, NoAccess, ReadOnly, ReadWrite, WriteCopy.

    Returns:
        bool: True if the protection change was successful, False otherwise.
    """
    page_prot = PageRightsConfiguration(page_rights)
    return dbgClient.virt_protect(addr, page_prot)

@mcp.tool()
def virt_free(addr: int) -> bool:
    """
    Free memory in the debuggee's address space.

    Args:
        addr (int): Address of the memory to free.

    Returns:
        bool: True if the memory free was successful, False otherwise.
    """
    return dbgClient.virt_free(addr)

@mcp.tool()
def memset(addr: int, byte_val: int, size: int) -> bool:
    """
    Set memory in the debuggee's address space to a specified byte value.

    Args:
        addr (int): Address of the memory to set.
        byte_val (int): Byte value to set the memory to.
        size (int): Number of bytes to set.

    Returns:
        bool: True if the memory set was successful, False otherwise.
    """
    return dbgClient.memset(addr, byte_val, size)


@mcp.tool()
def set_breakpoint(address_or_symbol: int | str,  name: str = None, bp_type: str ) -> bool:


def main():
    print("Starting the x64dbg MCP server!")
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()