# PhantomGate

**PhantomGate** is a minimalistic port-spoofer written in Python, designed to confuse and mislead port scanners by responding with fake or randomized signatures. Inspired by the approach of portspoof-like tools, **PhantomGate** uses a simple signature file to dynamically emulate different services.

> Created by **Vladislav Tislenko (aka keklick1337)**

## Features

- **Simple Setup**: Works out of the box with just Python 3 and a signature file.  
- **Minimal Dependencies**: Uses only the Python standard library.  
- **Randomized Responses**: Generates pseudo-random responses (for "regex" signatures).  
- **Flexible Configuration**: Customizable through command-line flags.  
- **Lightweight**: Single-file implementation, easy to deploy.

## Quick Start

1. **Clone or Download** this repository and place your signature file (`signatures.txt`) alongside `phantomgate.py`.
2. **Install** Python 3 (if not already installed).  
3. **Run**:
   ```bash
   python3 phantomgate.py -s signatures.txt -l 0.0.0.0:8888 -v
   ```
   - `-s signatures.txt`: Path to the signature file.  
   - `-l 0.0.0.0:8888`: Listen on all interfaces (`0.0.0.0`) port **8888**.  
   - `-v`: Enable verbose output.

Press **Ctrl+C** to stop the server.

## Signature File Format

- **Raw Signatures**: Lines without parentheses `(` or `)` are treated as **raw** payloads and can include escaped sequences like `\n`, `\r`, `\x41`, etc.
- **Regex Signatures**: Lines with parentheses `(` and `)` are treated as **regex** signatures. PhantomGate randomly generates a pseudo-regex-like response using rules for `\d`, `\w`, `[abc]`, `+`, `*`, `.` etc.

Example `signatures.txt`:
```
HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n
220 (vsFTPd 3.0.3)
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
```
- First line is interpreted as **raw**.  
- Second line has parentheses, so it's treated as **regex**.  
- Third line is **raw**.

## Usage Examples

- **Default** (listen on `127.0.0.1:8888`, use `signatures`):
  ```bash
  python3 phantomgate.py
  ```
- **Debug mode**:
  ```bash
  python3 phantomgate.py -s my_signatures.txt -l 127.0.0.1:9999 -d
  ```
- **Quiet mode** (only error messages):
  ```bash
  python3 phantomgate.py -q
  ```
- **Show version**:
  ```bash
  python3 phantomgate.py -V
  ```

## Redirecting All Traffic

To direct all incoming traffic for ports 1–65535 to PhantomGate’s port on **Linux**, you can use `iptables`:
```bash
INTERFACE="eth0"  # Replace with your network interface
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp -m tcp \
  -m multiport --dports 1:65535 -j REDIRECT --to-ports 8888
```
Then **PhantomGate** will effectively spoof any connection attempt on your machine.

## Contributing

Feel free to submit pull requests or open issues if you have ideas for improvements or bug fixes.

## License

Distributed under the **GNU License** (see [LICENSE](LICENSE) for details).

---

**Created by Vladislav Tislenko (aka [keklick1337](https://github.com/keklick1337))**.  