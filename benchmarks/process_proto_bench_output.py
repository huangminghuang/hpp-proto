#!/usr/bin/env python3
import re,sys,json
import argparse
import matplotlib.pyplot as plt

def parse_benchmark_output(output):
    # Regular expression pattern to capture benchmark rows with proto3::GoogleMessage1
    pattern = re.compile(r'(hpp_proto|google)_(deserialize|set_message|set_message_and_serialize)_(regular|arena|nonowning)<.+::proto3::GoogleMessage1>\s+([\d\.]+)\s+ns\s+([\d\.]+)\s+ns\s+(\d+)')
    
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
    return results

def speedup(results, operation, mode):
    google_time = results["google"][operation][mode]
    hpp_proto_time = results["hpp_proto"][operation][mode]
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
    ax.set_title(f"Operations CPU time on {args.platform}")

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
    plt.savefig(f"{args.platform}_bench.png", dpi=300)
    if show:
        plt.show()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process benchmark output and generate report')
    parser.add_argument('--platform', help='Platform name', required=True)
    parser.add_argument('--json', action='store_true', help='Generate JSON output')
    parser.add_argument('--chart', action='store_true', help='Generate chart output')
    parser.add_argument('--table', action='store_true', help='Generate HTML table output')
    parser.add_argument('-s', '--show', action='store_true', help='Show the chart')
    parser.add_argument('input', help='Input file')
    args = parser.parse_args()
    # Read benchmark output from stdin
    with open(args.input, 'r') as f:
        # Parse the benchmark output 
        results = parse_benchmark_output(f.read())
        if args.json:
            with open(f'{args.platform}_bench.json', 'w') as f:
                f.write(json.dumps(results, indent=4))
        if args.chart or args.show:
            gen_chart(args.platform, results, args.show)
        if args.table:
            print(generate_markdown_table(args.platform, results))
    