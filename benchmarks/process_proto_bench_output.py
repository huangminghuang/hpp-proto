#!/usr/bin/env python3
import re,sys

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
            results[lib_name][operation][mode] = [float(cpu_ns), int(iterations)]

    return results

def speedup(results, operation, mode):
    google_iterations = results["google"][operation][mode][1]
    hpp_proto_iterations = results["hpp_proto"][operation][mode][1]
    return hpp_proto_iterations/google_iterations*100


def generate_markdown_table(results):
    header = (
        "|           |      deserialize             |          set_message         |   set_message and serialize  |\n"
        "|-----------|------------------------------|------------------------------|------------------------------|\n"
        "|           |  regular  | arena/non_owning |  regular  | arena/non_owning |  regular  | arena/non_owning |\n"
        "|-----------|-----------|------------------|-----------|------------------|-----------|------------------|\n"
    )
    
    rows = []
    row = results["google"]

    for lib_name in ["google", "hpp_proto"]:
        row = results[lib_name]
        rows.append(f"| {lib_name:9} | {row['deserialize']['regular'][0]:6} ns | {row['deserialize']['arena/non_owning'][0]:13} ns | {row['set_message']['regular'][0]:6} ns | { row['set_message']['arena/non_owning'][0]:13} ns | {row['set_message_and_serialize']['regular'][0]:6} ns | { row['set_message_and_serialize']['arena/non_owning'][0]:13} ns |")

    rows.append("|-----------|-----------|------------------|-----------|------------------|-----------|------------------|")
    rows.append("| hpp_proto |           |                  |           |                  |           |                  |")
    rows.append(f"|  speedup  | {speedup(results,'deserialize','regular'):8.2f}% | {speedup(results,'deserialize','arena/non_owning'):15.2f}% | {speedup(results,'set_message','regular'):8.2f}% | {speedup(results,'set_message','arena/non_owning'):15.2f}% | {speedup(results,'set_message_and_serialize','regular'):8.2f}% | {speedup(results,'set_message_and_serialize','arena/non_owning'):15.2f}% |")

    # Combine header and rows
    return header + "\n".join(rows)

if __name__ == '__main__':
    # Read benchmark output from stdin
    benchmark_output = sys.stdin.read()

    # Parse the benchmark output and generate the Markdown table
    results = parse_benchmark_output(benchmark_output)
    markdown_table = generate_markdown_table(results)

    # Output the Markdown table
    print(markdown_table)