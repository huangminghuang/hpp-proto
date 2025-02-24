#!/usr/bin/env python3
import os, json
import matplotlib.pyplot as plt
import argparse

def collect_sizes(dir):
    result = {}
    files = ["google_decode_encode", "google_decode_encode_lite", "hpp_proto_decode_encode"]
    for f in files:
        result[f] = os.path.getsize(os.path.join(dir, f))
    return result

def gen_chart(platform, data):
    # Normalize values (hpp_proto_decode_encode = 1)
    base_value = data["hpp_proto_decode_encode"]
    normalized_data = {key: value / base_value for key, value in data.items()}

    # Extract labels, values, and actual values
    labels = list(normalized_data.keys())
    values = list(normalized_data.values())
    actual_values = list(data.values())  # Keep the original values for labeling

    # Create bar chart
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, values, color=["orange", "orange", "blue"])

    # Add actual value labels on top of bars
    for bar, actual in zip(bars, actual_values):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, height, f'{actual:,}',  # Format with commas
                ha='center', va='bottom', fontsize=12)

    # Labels and title
    ax.set_ylabel("Normalized Binary Sizes")
    ax.set_title(f"Binary Size Comparison on {platform}")

    # Rotate x-axis labels for better readability
    ax.set_xticklabels(labels, rotation=15)

    # Save and show chart
    plt.tight_layout()
    plt.savefig(f"{platform}_sizes.png", dpi=300)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Collect binary sizes and generate report')
    parser.add_argument('--platform', help='Platform name', required=True)
    parser.add_argument('dir', help='binary directory')
    args = parser.parse_args()

    sizes = collect_sizes(args.dir)
    with open(f"{args.platform}_sizes.json", "w") as f:
        json.dump(sizes, f)
    gen_chart(args.platform, sizes)