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
            results[lib_name][operation][mode] = float(cpu_ns)

    return results

def speedup(results, operation, mode):
    google_time = results["google"][operation][mode]
    hpp_proto_time = results["hpp_proto"][operation][mode]
    return google_time/hpp_proto_time


def generate_markdown_table(results):
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
    row = results["google"]

    for lib_name in ["google", "hpp_proto"]:
        row = results[lib_name]
        rows.append(" <tr>\n"
                    f"   <td>{lib_name} CPU time</td>\n"
                    f"   <td><div align=\"right\">{row['deserialize']['regular']}&nbsp;ns</div></td>\n"
                    f"   <td><div align=\"right\">{row['deserialize']['arena/non_owning']}&nbsp;ns</div></td>\n"
                    f"   <td><div align=\"right\">{row['set_message']['regular']}&nbsp;ns</div></td>\n"
                    f"   <td><div align=\"right\">{row['set_message']['arena/non_owning']}&nbsp;ns</div></td>\n"
                    f"   <td><div align=\"right\">{row['set_message_and_serialize']['regular']}&nbsp;ns</div></td>\n"
                    f"   <td><div align=\"right\">{row['set_message_and_serialize']['arena/non_owning']}&nbsp;ns</div></td>\n"
                    " </tr>")

    rows.append(" <tr>\n"
                f"   <td>hpp_proto speedup factor</td>\n"
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

if __name__ == '__main__':
    # Read benchmark output from stdin
    benchmark_output = sys.stdin.read()

    # Parse the benchmark output and generate the Markdown table
    results = parse_benchmark_output(benchmark_output)
    markdown_table = generate_markdown_table(results)

    # Output the Markdown table
    print(markdown_table)