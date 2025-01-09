#!/usr/bin/env python3
# ===============================================================
# PhantomGate (Python version, extended bracket parsing)
# Created by Vladislav Tislenko (keklick1337) in 2025
# A minimalistic Python port spoofer to confuse port scanners,
# with enhanced error handling, auto-fix for invalid signatures,
# and expanded bracket parsing in regex mode (mimicking the C99 logic).
# ===============================================================

import argparse
import random
import socket
import threading
import sys
import os
import logging
import shutil
from typing import Optional

VERSION = "0.1.3"
logger = logging.getLogger("phantomgate")

###############################################################################
# 1) LOG CONFIGURATION
###############################################################################
def configure_logging(debug: bool, verbose: bool, quiet: bool, logfile: Optional[str] = None) -> None:
    """
    Configures the logging level and format based on user arguments.
    If logfile is provided, logs are also written there with timestamps.
    """
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    if logfile:
        file_handler = logging.FileHandler(logfile, mode="a", encoding="utf-8")
        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    if debug:
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logger.setLevel(logging.INFO)
    elif quiet:
        logger.setLevel(logging.ERROR)
    else:
        logger.setLevel(logging.WARNING)


###############################################################################
# 2) SIGNATURE TYPES AND PARSING
###############################################################################
def looks_like_regex(line: str) -> bool:
    """
    Simple heuristic to decide if the line should be treated as a 'regex'.
    We check for backslash tokens (\\d, \\w, \\., \\x) or parentheses '(' / '['.
    """
    if "\\d" in line or "\\w" in line or "\\." in line or "\\x" in line:
        return True
    if "(" in line or "[" in line:
        return True
    return False


def auto_fix_regex(s: str) -> str:
    """
    Tries to 'auto-fix' unmatched parentheses or brackets:
      - If we see a ')' or ']' without a matching '(' or '[', replace with '_'.
      - If there are leftover '(' or '[', replace them with '_'.
    Minimally prevents crashes in the naive parser.
    """
    arr = list(s)
    open_paren = 0
    open_brack = 0

    # First pass: handle unmatched closing
    for i, c in enumerate(arr):
        if c == '(':
            open_paren += 1
        elif c == ')':
            if open_paren > 0:
                open_paren -= 1
            else:
                arr[i] = '_'
        elif c == '[':
            open_brack += 1
        elif c == ']':
            if open_brack > 0:
                open_brack -= 1
            else:
                arr[i] = '_'

    # Second pass: replace leftover '(' or '['
    if open_paren > 0 or open_brack > 0:
        for i, c in enumerate(arr):
            if open_paren > 0 and c == '(':
                arr[i] = '_'
                open_paren -= 1
            if open_brack > 0 and c == '[':
                arr[i] = '_'
                open_brack -= 1
            if open_paren == 0 and open_brack == 0:
                break

    return "".join(arr)


def parse_signatures(file_path: str):
    """
    Reads the signature file in binary mode, then decodes each line as Latin-1
    to preserve every possible 8-bit character. Returns a list of tuples:
      [("raw", b"...", b"original_line"), ("regex", "...", b"original_line"), ...]
    If a line looks like a regex, store ("regex", auto_fixed_string).
    Otherwise, treat it as raw, unescaping \\r, \\n, \\xNN, etc.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Could not open file: {file_path}")

    signatures = []
    with open(file_path, "rb") as f:
        # Read raw bytes, split by lines
        lines = f.read().splitlines()

    for idx, raw_line in enumerate(lines, start=1):
        # Remove trailing newlines: handle b'\r' and/or b'\n'
        raw_line = raw_line.rstrip(b"\r\n")
        if not raw_line.strip():
            continue

        # Decode as Latin-1 to preserve all 0-255 bytes
        try:
            line_decoded = raw_line.decode("latin-1")
        except UnicodeDecodeError:
            line_decoded = raw_line.decode("latin-1", errors="replace")

        line_stripped = line_decoded.strip()
        if not line_stripped:
            continue

        if looks_like_regex(line_stripped):
            # Regex type
            fixed_line = auto_fix_regex(line_stripped)
            signatures.append(("regex", fixed_line, raw_line))
        else:
            # Raw type
            unescaped = unescape_string(line_stripped)
            if unescaped is None:
                logger.warning("Line %d: unescape_string() failed, skipping...", idx)
                continue
            signatures.append(("raw", unescaped, raw_line))

    if not signatures:
        raise ValueError(f"Signature file is empty or invalid: {file_path}")

    logger.debug("Loaded %d signatures from '%s'", len(signatures), file_path)
    return signatures


###############################################################################
# 3) UNESCAPE LOGIC (LIKE C99)
###############################################################################
def unescape_string(s: str) -> bytes:
    """
    Similar to the C99 code:
      - \\xNN => parse two hex digits
      - \\0 => zero byte
      - \\n => newline, \\r => carriage return, \\t => tab
      - otherwise copy the next char after backslash literally.
    Returns bytes (may contain embedded zeros).
    """
    result = bytearray()
    i = 0
    length = len(s)

    while i < length:
        if s[i] == "\\" and i + 1 < length:
            nxt = s[i + 1]
            if nxt == "x" and i + 3 < length:
                # \xNN
                hex_part = s[i + 2 : i + 4]
                try:
                    byte_val = int(hex_part, 16)
                    result.append(byte_val)
                    i += 4
                    continue
                except ValueError:
                    # If invalid hex, just store "\\x"
                    result.extend(b"\\x")
                    i += 2
                    continue
            elif nxt == "0":
                result.append(0)
                i += 2
                continue
            elif nxt == "n":
                result.append(ord('\n'))
                i += 2
                continue
            elif nxt == "r":
                result.append(ord('\r'))
                i += 2
                continue
            elif nxt == "t":
                result.append(ord('\t'))
                i += 2
                continue
            else:
                # Copy that next char literally
                result.append(ord(nxt))
                i += 2
                continue
        else:
            result.append(ord(s[i]))
            i += 1

    return bytes(result)


###############################################################################
# 4) BRACKET EXPANSION + REGEX EXPANSION
###############################################################################
def expand_bracket_expression(src: str) -> str:
    """
    Expands bracket content with a C99-like logic:
      - \\w => A-Za-z0-9_
      - \\d => 0-9
      - \\. => literal '.'
      - \\r => literal '\r'
      - \\n => literal '\n'
      - \\t => literal '\t'
      - \\xNN => a single char with hex code NN (if valid)
      - everything else after '\' => that literal char
      - otherwise copy characters as-is.
    Example:
      "\\w._-" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
    We then pick exactly ONE random char from the expanded set for that bracket group.
    """
    result_chars = []
    i = 0
    length = len(src)

    while i < length:
        c = src[i]
        if c == "\\" and i + 1 < length:
            nxt = src[i + 1]
            if nxt == "w":
                # expand \w => A-Za-z0-9_
                word_chars = (
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz"
                    "0123456789_"
                )
                result_chars.extend(word_chars)
                i += 2
            elif nxt == "d":
                # expand \d => 0-9
                digits = "0123456789"
                result_chars.extend(digits)
                i += 2
            elif nxt == ".":
                # expand \. => literal '.'
                result_chars.append(".")
                i += 2
            elif nxt == "r":
                # expand \r => literal '\r'
                result_chars.append("\r")
                i += 2
            elif nxt == "n":
                # expand \n => literal '\n'
                result_chars.append("\n")
                i += 2
            elif nxt == "t":
                # expand \t => literal '\t'
                result_chars.append("\t")
                i += 2
            elif nxt == "x" and i + 3 < length:
                # \xNN
                hx = src[i + 2 : i + 4]
                try:
                    val = int(hx, 16)
                    result_chars.append(chr(val))
                    i += 4
                except ValueError:
                    result_chars.append("x")
                    i += 2
            else:
                # unrecognized or other: copy that next char literally
                result_chars.append(nxt)
                i += 2
        else:
            result_chars.append(c)
            i += 1

    return "".join(result_chars)


def pick_random_digit() -> str:
    """
    Returns a random digit [0-9].
    """
    return chr(ord('0') + random.randint(0, 9))


def pick_random_wchar() -> str:
    """
    Returns a random character in [A-Za-z0-9_] (like \\w).
    """
    r = random.randint(0, 62)
    if r < 26:
        return chr(ord('a') + r)
    r -= 26
    if r < 26:
        return chr(ord('A') + r)
    r -= 26
    if r < 10:
        return chr(ord('0') + r)
    return "_"


def pick_random_printable() -> str:
    """
    Returns a random ASCII character in [0x21..0x7E].
    """
    return chr(random.randint(0x21, 0x7E))


def pick_random_bracket(expanded_buf: str, last_c: str) -> str:
    """
    Picks exactly one random character from 'expanded_buf',
    trying not to match 'last_c' if possible.
    """
    if not expanded_buf:
        return "?"
    for _ in range(10):
        c = random.choice(expanded_buf)
        if c != last_c:
            return c
    return expanded_buf[0]


def pick_from_category(cat: str, bracket_buf: str, last_c: str) -> str:
    """
    Like the C99 logic: pick a random char from the last category
    (DIGIT, WCHAR, BRACKET, PRINTABLE, LITERAL).
    Avoid repeating 'last_c' if possible.
    """
    for _ in range(10):
        if cat == "DIGIT":
            c = pick_random_digit()
        elif cat == "WCHAR":
            c = pick_random_wchar()
        elif cat == "BRACKET":
            c = pick_random_bracket(bracket_buf, last_c)
        elif cat == "PRINTABLE":
            c = pick_random_printable()
        else:
            # fallback for LITERAL or unknown
            c = pick_random_printable()

        if c != last_c:
            return c
    return pick_random_printable()


def generate_regex_match(regex_str: str) -> bytes:
    """
    Naive 'regex-like' expansion, including:
      - \\d, \\w, \\r, \\n, \\t, \\0, \\xNN
      - bracket expansions [ ... ] => expand bracket, then pick 1 random char
      - + => 1..6 repetitions from the last category
      - * => 0..5 repetitions from the last category
      - '.' => random printable
      - everything else => literal
    """
    result_chars = []
    i = 0
    length = len(regex_str)

    last_char = ""
    last_cat = "NONE"
    bracket_buf = ""  # we store the expanded bracket expression here

    while i < length:
        c = regex_str[i]

        # Handle backslash-escaped sequences
        if c == "\\" and (i + 1 < length):
            nxt = regex_str[i + 1]
            outc = None
            cat = "LITERAL"
            skip = 2

            if nxt == "d":
                outc = pick_random_digit()
                cat = "DIGIT"
            elif nxt == "w":
                outc = pick_random_wchar()
                cat = "WCHAR"
            elif nxt == "r":
                outc = "\r"
            elif nxt == "n":
                outc = "\n"
            elif nxt == "t":
                outc = "\t"
            elif nxt == "0":
                outc = "\x00"
            elif nxt == "x" and (i + 3 < length):
                # \xNN
                hx = regex_str[i + 2 : i + 4]
                try:
                    val = int(hx, 16)
                    outc = chr(val)
                    skip = 4
                except ValueError:
                    outc = "x"
            else:
                # default: literal next char
                outc = nxt

            # If this was a random category, try to avoid duplicating last_char
            if cat in ("DIGIT", "WCHAR", "PRINTABLE") and outc == last_char and outc != "\x00":
                outc = pick_from_category(cat, bracket_buf, last_char)

            result_chars.append(outc)
            last_char = outc
            last_cat = cat
            bracket_buf = ""  # reset bracket buffer
            i += skip

        elif c == "[":
            # Collect everything until closing ']'
            j = i + 1
            raw_buf = []
            while j < length and regex_str[j] != "]":
                raw_buf.append(regex_str[j])
                j += 1

            # Expand bracket expression
            raw_str = "".join(raw_buf)
            expanded = expand_bracket_expression(raw_str)
            if not expanded:
                expanded = "?"
            outc = pick_random_bracket(expanded, last_char)

            result_chars.append(outc)
            last_char = outc
            last_cat = "BRACKET"
            bracket_buf = expanded

            if j < length:
                i = j + 1
            else:
                i = j

        elif c == "+":
            # 1..6 repeats of the previous category
            repeat_count = 1 + random.randint(0, 5)
            for _ in range(repeat_count):
                nc = pick_from_category(last_cat, bracket_buf, last_char)
                result_chars.append(nc)
                last_char = nc
            i += 1

        elif c == "*":
            # 0..5 repeats of the previous category
            repeat_count = random.randint(0, 5)
            for _ in range(repeat_count):
                nc = pick_from_category(last_cat, bracket_buf, last_char)
                result_chars.append(nc)
                last_char = nc
            i += 1

        elif c == ".":
            # Random printable
            cat = "PRINTABLE"
            nc = pick_random_printable()
            if nc == last_char:
                nc = pick_from_category(cat, bracket_buf, last_char)
            result_chars.append(nc)
            last_char = nc
            last_cat = cat
            bracket_buf = ""
            i += 1

        else:
            # Literal character
            result_chars.append(c)
            last_char = c
            last_cat = "LITERAL"
            bracket_buf = ""
            i += 1

    # Convert final string to bytes (Latin-1 to preserve 0x00..0xFF)
    return "".join(result_chars).encode("latin-1", errors="replace")


###############################################################################
# 5) SIGNATURE EXPANSION AND SERVER
###############################################################################
def generate_payload(signature):
    """
    If signature is ('raw', b'some_bytes', ...), return it as-is.
    If signature is ('regex', 'some_pattern', ...), expand it with generate_regex_match().
    """
    sig_type, data, _original_line = signature
    if sig_type == "raw":
        return data
    elif sig_type == "regex":
        return generate_regex_match(data)
    return b""


def is_printable_byte(byte: int) -> bool:
    """
    Checks if a single byte is printable (ASCII range 32-126 or tab/newline).
    """
    return 32 <= byte <= 126 or byte in (9, 10, 13)  # printable ASCII + \t, \n, \r


def byte_to_readable(byte: int) -> str:
    """
    Converts a single byte to a readable format.
    If the byte is printable, return the character.
    If not printable, return the byte as a HEX string (e.g., '\\xAA').
    """
    if is_printable_byte(byte):
        return chr(byte)
    else:
        return f"\\x{byte:02X}"


def format_signature_line(orig_line: bytes) -> str:
    """
    Formats a binary signature line into a readable format:
    - Printable bytes are displayed as characters.
    - Non-printable bytes are displayed as HEX strings.
    """
    return "".join(byte_to_readable(byte) for byte in orig_line)


def handle_client(conn: socket.socket, addr, signatures, debug, verbose, report_clients):
    """
    Handles a single connection in a separate thread.
    Randomly selects a signature, generates a payload, and sends it to the client.
    If report_clients is on, logs which signature was sent (truncated to terminal width).
    """
    try:
        max_attempts = 5
        payload = None
        chosen_index = -1

        for _ in range(max_attempts):
            idx = random.randint(0, len(signatures) - 1)
            sig = signatures[idx]
            candidate = generate_payload(sig)
            if candidate and len(candidate) > 0:
                payload = candidate
                chosen_index = idx
                break

        if not payload:
            logger.error("No valid payload found after multiple attempts; closing connection.")
            conn.close()
            return

        # Send all bytes (including any \0)
        conn.sendall(payload)

        # Standard debug message (if debug, but not forced to show signature)
        if debug and not report_clients:
            logger.debug("Sent payload (%d bytes) to %s [sig:%d]",
                         len(payload), addr, chosen_index)

        # If report_clients is enabled, show the original signature truncated
        if report_clients and chosen_index != -1:
            sig_type, _data, orig_line = signatures[chosen_index]
            sig_str = format_signature_line(orig_line)

            term_width = shutil.get_terminal_size().columns
            if term_width < 10:
                term_width = 80

            if len(sig_str) > term_width:
                sig_str = sig_str[:term_width]

            logger.debug("Client %s got signature index %d: %s", str(addr), chosen_index, sig_str)

        elif verbose:
            logger.info("Sent payload to %s", str(addr))

    except BrokenPipeError:
        if debug:
            logger.debug("Connection reset by %s", str(addr))
    except Exception as e:
        logger.error("Could not send data to %s: %s", str(addr), e)
    finally:
        conn.close()


def start_server(host: str, port: int, signatures, debug: bool, verbose: bool,
                 quiet: bool, report_clients: bool):
    """
    Creates a socket, binds, listens, and spawns a thread for each client.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
    except Exception as e:
        logger.error("Could not bind to %s:%d: %s", host, port, e)
        sys.exit(1)

    server_socket.listen()

    if not quiet:
        logger.info("PhantomGate is listening on %s:%d", host, port)

    while True:
        try:
            conn, addr = server_socket.accept()
        except KeyboardInterrupt:
            if not quiet:
                logger.info("Stopping the server.")
            break

        if debug:
            logger.debug("Accepted connection from %s", str(addr))

        client_thread = threading.Thread(
            target=handle_client,
            args=(conn, addr, signatures, debug, verbose, report_clients),
            daemon=True
        )
        client_thread.start()

    server_socket.close()


###############################################################################
# 6) MAIN
###############################################################################
def main():
    parser = argparse.ArgumentParser(
        description="PhantomGate - a minimalistic port spoofer in Python."
    )
    parser.add_argument("-s", "--signatures",
                        default="signatures.txt",
                        help="Path to the signature file (default: 'signatures.txt').")
    parser.add_argument("-l", "--listen",
                        default="127.0.0.1:8888",
                        help="Host:port to listen on, e.g. '127.0.0.1:8888'.")
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        help="Enable debug output (do not show signature banners).")
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Enable verbose output.")
    parser.add_argument("-q", "--quiet",
                        action="store_true",
                        help="Only show error messages.")
    parser.add_argument("-V", "--version",
                        action="store_true",
                        help="Show version and exit.")
    parser.add_argument("-r", "--report-clients",
                        action="store_true",
                        help="Show which signature was sent to which client (single line, truncated). Automatically sets debug on.")
    parser.add_argument("-f", "--logfile",
                        help="Path to a logfile where output will also be saved with timestamps.")

    args = parser.parse_args()

    if args.version:
        print(f"PhantomGate version {VERSION}")
        sys.exit(0)

    # If report-clients is on, force debug to True
    if args.report_clients:
        args.debug = True

    configure_logging(args.debug, args.verbose, args.quiet, args.logfile)

    # Load signatures from file
    try:
        signatures = parse_signatures(args.signatures)
    except Exception as e:
        logger.error("%s", e)
        sys.exit(1)

    # Parse host:port
    if ":" not in args.listen:
        logger.error("Listen address must be in the format 'host:port'.")
        sys.exit(1)

    host, port_str = args.listen.split(":")
    try:
        port = int(port_str)
        if port <= 0 or port > 65535:
            raise ValueError
    except ValueError:
        logger.error("Invalid port number: %s", port_str)
        sys.exit(1)

    start_server(
        host,
        port,
        signatures,
        args.debug,
        args.verbose,
        args.quiet,
        args.report_clients
    )


if __name__ == "__main__":
    main()
