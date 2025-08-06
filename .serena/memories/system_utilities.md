# System Utilities for Darwin (macOS)

## File System Commands
- `ls`: List directory contents
- `cd`: Change directory
- `pwd`: Print working directory
- `mkdir`: Create directories
- `rm`: Remove files/directories
- `cp`: Copy files/directories
- `mv`: Move/rename files
- `touch`: Create empty files
- `chmod`: Change file permissions
- `chown`: Change file ownership

## Text Processing
- `grep`: Search text patterns
- `rg` (ripgrep): Fast recursive grep (recommended)
- `find`: Find files and directories
- `cat`: Display file contents
- `head`/`tail`: View file beginning/end
- `less`/`more`: Page through files
- `sed`: Stream editor
- `awk`: Text processing

## Development Tools
- `git`: Version control
- `cargo`: Rust package manager and build tool
- `rustc`: Rust compiler
- `rustfmt`: Rust code formatter
- `clippy`: Rust linter
- `brew`: Homebrew package manager for macOS

## Process Management
- `ps`: List processes
- `top`: Monitor system resources
- `lsof`: List open files
- `kill`: Terminate processes

## Network Tools
- `curl`/`wget`: Download files
- `ssh`: Secure shell
- `scp`: Secure copy over network

## Archive Tools
- `tar`: Archive files
- `zip`/`unzip`: Compress files
- `gzip`/`gunzip`: GNU compression

## Environment
- `env`: Display environment variables
- `export`: Set environment variables
- `source`: Execute commands from file
- `which`: Locate command
- `whereis`: Locate binary, source, manual

## Special Darwin/macOS Notes
- Use `brew` for installing system dependencies
- `open` command to open files with default application
- `.DS_Store` files are created by Finder (add to .gitignore)
- Case-insensitive filesystem by default
- Different command options compared to Linux (BSD vs GNU)

## Python/Security Agent Tools
- `uv`: Fast Python package installer and resolver
- `python`/`python3`: Python interpreter
- `dot`: Graphviz for generating visualizations