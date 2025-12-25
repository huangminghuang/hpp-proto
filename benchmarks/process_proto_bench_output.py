#!/usr/bin/env python3
import re,sys,json,os,platform,subprocess,shutil,shlex
import argparse
import matplotlib.pyplot as plt

def _read_first_match(path, prefix):
    with open(path, "r") as f:
        for line in f:
            if line.startswith(prefix):
                return line.strip().split("=", 1)[-1]
    return None

def _find_cmake_cache(start_path):
    start_dir = start_path
    if os.path.isfile(start_path):
        start_dir = os.path.dirname(start_path)
    current = os.path.abspath(start_dir)
    while True:
        candidate = os.path.join(current, "CMakeCache.txt")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None

def _compiler_from_cache(cache_path):
    if not cache_path or not os.path.isfile(cache_path):
        return None
    compiler = (
        _read_first_match(cache_path, "CMAKE_CXX_COMPILER:FILEPATH=") or
        _read_first_match(cache_path, "CMAKE_CXX_COMPILER:PATH=") or
        _read_first_match(cache_path, "CMAKE_CXX_COMPILER=")
    )
    if not compiler:
        return None
    def _read_compiler_version(compiler_path):
        compiler_args = shlex.split(compiler_path) if isinstance(compiler_path, str) else [compiler_path]
        result = subprocess.run(
            compiler_args + ["-v"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        return result.stdout

    output_text = _read_compiler_version(compiler)
    match = re.search(r'(Apple clang|clang|gcc) version ([0-9]+\.[0-9]+\.[0-9]+)', output_text)
    if match:
        return f"{match.group(1)} {match.group(2)}"
    return os.path.basename(compiler)

def _os_string(platform_name):
    if platform_name == "Mac":
        mac_ver = platform.mac_ver()[0]
        return f"MacOS {mac_ver}" if mac_ver else "MacOS"
    if platform_name == "Linux":
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.strip().split("=", 1)[1].strip('"')
        except Exception:
            pass
        return "Linux"
    return None

def _cpu_string(platform_name):
    if platform_name == "Mac":
        try:
            output = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
            if output:
                return output
        except Exception:
            pass
    if platform_name == "Linux":
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if line.startswith("model name"):
                        return line.split(":", 1)[1].strip()
        except Exception:
            pass
    return platform.processor() or platform.machine()

def _replace_cell(cell_text, new_value):
    if cell_text is None:
        return f" {new_value} "
    leading = re.match(r"^\s*", cell_text).group(0)
    trailing = re.search(r"\s*$", cell_text).group(0)
    return f"{leading}{new_value}{trailing}"

def update_readme(platform_name, input_path, readme_path):
    cache_path = _find_cmake_cache(input_path)
    compiler = _compiler_from_cache(cache_path) if cache_path else None
    os_name = _os_string(platform_name)
    cpu_name = _cpu_string(platform_name)
    print(f"Detected system info for {platform_name}: OS={os_name}, CPU={cpu_name}, Compiler={compiler}")
    if not (compiler and os_name and cpu_name):
        print("Warning: missing system info for README update.", file=sys.stderr)
        return

    row_re = re.compile(r"^\|(?P<label>[^|]+)\|(?P<mac>[^|]+)\|(?P<linux>[^|]+)\|\s*$")
    updated = False
    with open(readme_path, "r") as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        match = row_re.match(line)
        if not match:
            continue
        label = match.group("label").strip()
        if label not in {"OS", "CPU", "Compiler"}:
            continue
        mac_cell = match.group("mac")
        linux_cell = match.group("linux")
        if platform_name == "Mac":
            if label == "OS":
                mac_cell = _replace_cell(mac_cell, os_name)
            elif label == "CPU":
                mac_cell = _replace_cell(mac_cell, cpu_name)
            elif label == "Compiler":
                mac_cell = _replace_cell(mac_cell, compiler)
        elif platform_name == "Linux":
            if label == "OS":
                linux_cell = _replace_cell(linux_cell, os_name)
            elif label == "CPU":
                linux_cell = _replace_cell(linux_cell, cpu_name)
            elif label == "Compiler":
                linux_cell = _replace_cell(linux_cell, compiler)
        else:
            continue
        lines[i] = f"|{match.group('label')}|{mac_cell}|{linux_cell}|\n"
        updated = True

    if updated:
        with open(readme_path, "w") as f:
            f.writelines(lines)
    else:
        print("Warning: README update skipped; no matching rows found.", file=sys.stderr)

def parse_benchmark_output(output):
    # Regular expression pattern to capture benchmark rows with proto3::GoogleMessage1
    pattern = re.compile(r'(hpp_proto|google)_(deserialize|set_message|set_message_and_serialize)_(regular|arena|nonowning)<\s*.+::proto3::GoogleMessage1(?:<[^>]*>)?\s*>\s+([\d\.]+)\s+ns\s+([\d\.]+)\s+ns\s+(\d+)')
    
    # Dictionary to hold extracted benchmark data
    results = {
        "google": {"deserialize": {"regular": None, "arena/non_owning": None}, 
                        "set_message": {"regular": None, "arena/non_owning": None},
                        "set_message_and_serialize":{"regular": None, "arena/non_owning": None} },
        "hpp_proto": {"deserialize": {"regular": None, "arena/non_owning": None}, 
                        "set_message": {"regular": None, "arena/non_owning": None},
                        "set_message_and_serialize":{"regular": None, "arena/non_owning": None} }
    }
    
    # Process each line of the output
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            lib_name, operation, mode, time_ns, cpu_ns, iterations = match.groups() 
            if mode != "regular":
                mode = "arena/non_owning"
            results[lib_name][operation][mode] = float(cpu_ns)

    results["google protobuf"] = results.pop("google")
    results["hpp-proto"] = results.pop("hpp_proto")
    missing = []
    for lib_name, ops in results.items():
        for op_name, modes in ops.items():
            for mode_name, value in modes.items():
                if value is None:
                    missing.append(f"{lib_name}:{op_name}:{mode_name}")
                    modes[mode_name] = 0.0
    if missing:
        print("Warning: missing benchmark data, defaulting to 0.0 for:", file=sys.stderr)
        print("  " + ", ".join(missing), file=sys.stderr)
    return results

def speedup(results, operation, mode):
    google_time = results["google protobuf"][operation][mode]
    hpp_proto_time = results["hpp-proto"][operation][mode]
    return google_time/hpp_proto_time


def generate_markdown_table(platform, results):
    header = """<table><thead>
  <tr>
    <th colspan="7"> Operations CPU time</th>
  </tr></thead>
<tbody>
  <tr>
    <td></td>
    <td colspan="2">deserialize</td>
    <td colspan="2">set_message</td>
    <td colspan="2">set_message and serialize</td>
  </tr>
  <tr>
    <td></td>
    <td>regular</td>
    <td>arena/non_owning</td>
    <td>regular</td>
    <td>arena/non_owning</td>
    <td>regular</td>
    <td>arena/non_owning</td>
  </tr>
"""    
    rows = []
    row = results["google protobuf"]

    for lib_name in ["google protobuf", "hpp-proto"]:
        row = results[lib_name]
        rows.append(" <tr>\n"
                    f"   <td>{lib_name} CPU time on {platform}</td>\n"
                    f"   <td><div align=\"right\">{row['deserialize']['regular']}&nbsp;ns</div></td>\n"
                    f"   <td><div align=\"right\">{row['deserialize']['arena/non_owning']}&nbsp;ns</div></td>\n"
                    f"   <td><div align=\"right\">{row['set_message']['regular']}&nbsp;ns</div></td>\n"
                    f"   <td><div align=\"right\">{row['set_message']['arena/non_owning']}&nbsp;ns</div></td>\n"
                    f"   <td><div align=\"right\">{row['set_message_and_serialize']['regular']}&nbsp;ns</div></td>\n"
                    f"   <td><div align=\"right\">{row['set_message_and_serialize']['arena/non_owning']}&nbsp;ns</div></td>\n"
                    " </tr>")

    rows.append(" <tr>\n"
                f"   <td>hpp-proto speedup factor</td>\n"
                f"   <td><div align=\"right\">{speedup(results,'deserialize','regular'):4.2f}</div></td>\n"
                f"   <td><div align=\"right\">{speedup(results,'deserialize','arena/non_owning'):4.2f}</div></td>\n"
                f"   <td><div align=\"right\">{speedup(results,'set_message','regular'):4.2f}</div></td>\n"
                f"   <td><div align=\"right\">{speedup(results,'set_message','arena/non_owning'):4.2f}</div></td>\n"
                f"   <td><div align=\"right\">{speedup(results,'set_message_and_serialize','regular'):4.2f}</div></td>\n"
                f"   <td><div align=\"right\">{speedup(results,'set_message_and_serialize','arena/non_owning'):4.2f}</div></td>\n"
                " </tr>\n"
                "</tbody>\n"
                "</table>\n")

    # Combine header and rows
    return header + "\n".join(rows)

def gen_chart(platform, data, show):
    libs = list(data.keys())  # Libraries (google, hpp-proto)
    operations = list(data[libs[0]].keys())  # Operations (deserialize, set_message, set_message_and_serialize)
    variations = list(data[libs[0]][operations[0]].keys())  # Subcategories (normal, arena/non-owning)

    # Configurations for spacing
    num_variations = len(variations)
    num_libs = len(libs)
    num_operations = len(operations)
    width = 0.2  # Width of each bar
    small_gap = 0.3  # Small space between variations
    big_gap = 0.5  # Large space between operations

    # Compute x positions for bars
    x_positions = []
    current_x = 0
    for op_idx in range(num_operations):
        for var_idx in range(num_variations):
            for lib_idx in range(num_libs):
                x_positions.append(current_x)
                current_x += width  # Normal bar spacing
            current_x += small_gap  # Add small space between variations
        current_x += big_gap  # Add large space between operations

    # Define colors for each library
    library_colors = {"hpp-proto": "blue", "google protobuf": "orange"}  # Assign colors

    # Create the plot
    fig, ax = plt.subplots(figsize=(10, 6))

    # Initialize dictionary for legend
    legend_handles = {}

    # Plot bars for each variation-library combination
    for i in range(len(x_positions)):
        op_idx = i // (num_variations * num_libs)  # Get algorithm index
        var_idx = (i % (num_variations * num_libs)) // num_libs  # Get variation index
        lib_idx = i % num_libs  # Get library index

        library_name = libs[lib_idx]
        operation = operations[op_idx]
        variation = variations[var_idx]
        
        # Add the bar and store one legend entry per library
        bar = ax.bar(x_positions[i], data[library_name][operation][variation], width, 
                    color=library_colors[library_name])
        
        # Store only the first occurrence of each library for the legend
        if library_name not in legend_handles:
            legend_handles[library_name] = bar[0]

    # Labels and title
    ax.set_ylabel("Execution Time (ns)")
    ax.set_title(f"Operations CPU time on {platform}")

    # **Primary X-Ticks: Variations (Placed Under the Bars)**
    var_x_positions = []
    var_labels = []
    for i in range(num_operations):
        base_idx = i * num_variations * num_libs
        for j in range(num_variations):
            start_idx = base_idx + j * num_libs
            var_x_positions.append(sum(x_positions[start_idx:start_idx + num_libs]) / num_libs)
            var_labels.append(variations[j])

    ax.set_xticks(var_x_positions)
    ax.set_xticklabels(var_labels)

    # **Secondary X-Ticks for Options Labels (Below Variations)**
    algo_x_positions = [sum(x_positions[i:i+num_variations*num_libs]) / (num_variations*num_libs) 
                        for i in range(0, len(x_positions), num_variations*num_libs)]
    ax2 = ax.secondary_xaxis('bottom')
    ax2.set_xticks(algo_x_positions)
    ax2.set_xticklabels(operations)
    ax2.spines['bottom'].set_visible(False)  # 🔹 Remove the horizontal line
    ax2.spines['bottom'].set_position(('outward', 20))  # Adjust position downward
    ax2.tick_params(length=0)  # Remove tick marks

    # **Legend Only Showing Platforms**
    ax.legend(legend_handles.values(), legend_handles.keys(), title="Libraries", loc="upper left", bbox_to_anchor=(1,1))  

    # Save the chart
    plt.tight_layout()
    plt.savefig(f"{platform}_bench.png", dpi=300)
    if show:
        plt.show()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process benchmark output and generate report')
    parser.add_argument('--platform', help='Platform name', required=True)
    parser.add_argument('--json', action='store_true', help='Generate JSON output')
    parser.add_argument('--chart', action='store_true', help='Generate chart output')
    parser.add_argument('--table', action='store_true', help='Generate HTML table output')
    parser.add_argument('-s', '--show', action='store_true', help='Show the chart')
    parser.add_argument('--cmake-cache', help='Path to CMakeCache.txt')
    parser.add_argument('input', help='Input file')
    args = parser.parse_args()
    # Read benchmark output from stdin
    with open(args.input, 'r') as f:
        # Parse the benchmark output 
        results = parse_benchmark_output(f.read())
        readme_path = os.path.join(os.path.dirname(__file__), "ReadMe.md")
        if args.json:
            with open(f'{args.platform}_bench.json', 'w') as f:
                f.write(json.dumps(results, indent=4))
        if args.chart or args.show:
            gen_chart(args.platform, results, args.show)
        if args.table:
            print(generate_markdown_table(args.platform, results))
        if os.path.isfile(readme_path):
            cache_input = args.cmake_cache or args.input
            update_readme(args.platform, cache_input, readme_path)
    
