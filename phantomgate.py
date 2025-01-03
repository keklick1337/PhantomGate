#!/usr/bin/env python3
# ===============================================================
# PhantomGate
# Created by Vladislav Tislenko (keklick1337) in 2025
# A minimalistic Python port spoofer to confuse port scanners.
# ===============================================================

import argparse
import random
import socket
import threading
import sys
import os
import logging

VERSION = "0.1.0"

logger = logging.getLogger("phantomgate")

def configure_logging(debug: bool, verbose: bool, quiet: bool) -> None:
    """
    Sets up the logging level and format based on user arguments.
    """
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    if debug:
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logger.setLevel(logging.INFO)
    elif quiet:
        logger.setLevel(logging.ERROR)
    else:
        # Default logging level if none of the flags are set
        logger.setLevel(logging.WARNING)


def parse_signatures(file_path: str):
    """
    Reads the signature file and returns a list of items in the form:
    [("raw", b"byte_data"), ("regex", "regex_string"), ...].
    If the line contains parentheses '()', it is treated as a regex signature;
    otherwise it's considered raw data.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Could not open file: {file_path}")

    signatures = []
    with open(file_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            if "(" in line and ")" in line:
                signatures.append(("regex", line))
            else:
                unescaped = unescape_string(line)
                signatures.append(("raw", unescaped))

    if not signatures:
        raise ValueError("Signature file is empty or contains no valid lines.")

    logger.debug("Loaded %d signatures from '%s'", len(signatures), file_path)
    return signatures


def unescape_string(s: str) -> bytes:
    """
    Converts escaped characters such as \n, \r, \\xNN, \0, etc. to corresponding bytes.
    Returns a bytes object.
    """
    result = bytearray()
    i = 0
    length = len(s)

    while i < length:
        c = s[i]
        if c == "\\" and (i + 1 < length):
            nxt = s[i + 1]
            if nxt == "x" and (i + 3 < length):
                # \xNN
                hex_part = s[i + 2 : i + 4]
                try:
                    byte_val = int(hex_part, 16)
                    result.append(byte_val)
                    i += 4
                    continue
                except ValueError:
                    # If invalid hex, insert as-is
                    result.extend(b"\\x")
                    i += 2
                    continue
            elif nxt == "0":
                result.append(0)
                i += 2
                continue
            elif nxt == "n":
                result.append(ord("\n"))
                i += 2
                continue
            elif nxt == "r":
                result.append(ord("\r"))
                i += 2
                continue
            elif nxt == "t":
                result.append(ord("\t"))
                i += 2
                continue
            else:
                # Any other character after '\'
                result.append(ord(nxt))
                i += 2
                continue
        else:
            result.append(ord(c))
            i += 1

    return bytes(result)


def generate_payload(signature):
    """
    Generates the final payload based on the signature type.
    If it's 'raw', returns bytes as is.
    If it's 'regex', produces a pseudo-random string based on simplified rules.
    """
    sig_type, data = signature
    if sig_type == "raw":
        return data
    elif sig_type == "regex":
        return generate_regex_match(data)
    return b""


def generate_regex_match(regex_str: str) -> bytes:
    """
    Very simplified generator for a pseudo-random string from a 'regex'-like pattern.
    Handles: \\d, \\w, \\xNN, +, *, ., (), [].
    Returns bytes.
    """
    result = []
    i = 0
    length = len(regex_str)

    while i < length:
        c = regex_str[i]
        if c == "\\":
            if i + 1 < length:
                nxt = regex_str[i + 1]
                if nxt == "d":
                    # Digits 0-9
                    result.append(str(random.randint(0, 9)))
                    i += 2
                    continue
                elif nxt == "w":
                    # Letters a-z
                    char_letter = chr(random.randint(ord("a"), ord("z")))
                    result.append(char_letter)
                    i += 2
                    continue
                elif nxt == "x" and (i + 3 < length):
                    # \xNN
                    hex_part = regex_str[i + 2 : i + 4]
                    try:
                        val = int(hex_part, 16)
                        result.append(chr(val))
                        i += 4
                        continue
                    except ValueError:
                        result.append("\\x")
                        i += 2
                        continue
                else:
                    result.append(nxt)
                    i += 2
                    continue
        elif c == "[":
            # Find the closing bracket
            j = i + 1
            char_class = []
            while j < length and regex_str[j] != "]":
                char_class.append(regex_str[j])
                j += 1
            if char_class:
                chosen = random.choice(char_class)
                result.append(chosen)
            i = j + 1
            continue
        elif c == "(":
            # Skip until matching ')'
            depth = 1
            j = i + 1
            while j < length and depth > 0:
                if regex_str[j] == "(":
                    depth += 1
                elif regex_str[j] == ")":
                    depth -= 1
                j += 1
            i = j
            continue
        elif c in ["+", "*"]:
            # Repeat the last character 0-4 times
            if result:
                last_char = result[-1]
                repeat = random.randint(0, 4)
                for _ in range(repeat):
                    result.append(last_char)
            i += 1
            continue
        elif c == ".":
            # Any printable ASCII symbol
            code = random.randint(33, 126)
            result.append(chr(code))
            i += 1
            continue
        else:
            result.append(c)
            i += 1

    return "".join(result).encode("utf-8")


def handle_client(conn: socket.socket, addr, signatures, debug, verbose):
    """
    Handles a single connection in a separate thread.
    Chooses a random signature, generates payload, sends it to the client.
    """
    try:
        signature = random.choice(signatures)
        payload = generate_payload(signature)
        if payload:
            conn.sendall(payload)
            if debug:
                logger.debug("Sent payload (%d bytes) to %s", len(payload), addr)
            elif verbose:
                logger.info("Sent payload to %s", str(addr))
    except BrokenPipeError:
        if debug:
            logger.debug("Connection reset by %s", str(addr))
    except Exception as e:
        logger.error("Could not send data to %s: %s", str(addr), e)
    finally:
        conn.close()


def start_server(host: str, port: int, signatures, debug: bool, verbose: bool, quiet: bool):
    """
    Creates and starts the main server socket, accepting connections
    and spawning handler threads for each client.
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
            args=(conn, addr, signatures, debug, verbose),
            daemon=True
        )
        client_thread.start()

    server_socket.close()


def main():
    parser = argparse.ArgumentParser(description="PhantomGate - a minimalistic port spoofer in Python.")
    parser.add_argument("-s", "--signatures",
                        default="signatures.txt",
                        help="Path to the signature file (default: 'signatures.txt').")
    parser.add_argument("-l", "--listen",
                        default="127.0.0.1:8888",
                        help="Host:port to listen on (e.g. '127.0.0.1:8888').")
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        help="Enable debug output.")
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Enable verbose output.")
    parser.add_argument("-q", "--quiet",
                        action="store_true",
                        help="Only show error messages.")
    parser.add_argument("-V", "--version",
                        action="store_true",
                        help="Show version and exit.")

    args = parser.parse_args()

    if args.version:
        print(f"PhantomGate version {VERSION}")
        sys.exit(0)

    # Configure logging based on user flags
    configure_logging(args.debug, args.verbose, args.quiet)

    # Load signatures
    try:
        signatures = parse_signatures(args.signatures)
    except Exception as e:
        logger.error("%s", e)
        sys.exit(1)

    # Parse host and port from --listen
    listen_str = args.listen
    if ":" not in listen_str:
        logger.error("Listen address must be in the format 'host:port'.")
        sys.exit(1)

    host, port_str = listen_str.split(":")
    try:
        port = int(port_str)
    except ValueError:
        logger.error("Invalid port number: %s", port_str)
        sys.exit(1)

    # Start the server
    start_server(host, port, signatures, args.debug, args.verbose, args.quiet)


if __name__ == "__main__":
    main()
