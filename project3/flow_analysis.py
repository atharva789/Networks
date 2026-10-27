# Name: Atharva Gupta
# Case Network ID: axg1395
# date created: 10/27/2026
# date updated: 10/27/2026
# filename: flow_analysis.py
# description: reads the flow output of './proj3 -n' on stdin and measures how concentrated
# payload bytes are across flows. Prints a summary table and writes the plot used in
# report.pdf as an SVG file. Uses only the Python standard library.
# usage: ./proj3 -n -r trace_file | python3 flow_analysis.py plot.svg

import math
import sys

FLOW_FIELDS = 11
A_TO_B_BYTES_FIELD = 9
B_TO_A_BYTES_FIELD = 10
PERCENT = 100.0

# Rows printed in the summary table, as a percent of flows.
TABLE_PERCENTS = [0.01, 0.1, 1, 10, 50, 100]
# The point labelled on the plot.
HIGHLIGHT_PERCENT = 0.01

# Plot layout, in SVG units. The x axis is log scaled from 0.001% to 100% of flows.
WIDTH = 640
HEIGHT = 400
MARGIN_LEFT = 70
MARGIN_RIGHT = 25
MARGIN_TOP = 40
MARGIN_BOTTOM = 60
LABEL_GAP = 18
TICK_GAP = 10
X_MIN_EXP = -3
X_MAX_EXP = 2
Y_STEP = 20
POINTS_PER_DECADE = 40
CURVE_COLOR = "#1f5fa8"
MARK_COLOR = "#c0392b"
GRID_COLOR = "#dddddd"


def read_flow_bytes(lines):
    """Return the total payload bytes (A to B plus B to A) of each flow."""
    flow_bytes = []
    for line_num, line in enumerate(lines, 1):
        fields = line.split()
        if len(fields) != FLOW_FIELDS:
            sys.exit("error: line %d is not a proj3 -n flow record" % line_num)
        try:
            flow_bytes.append(int(fields[A_TO_B_BYTES_FIELD]) + int(fields[B_TO_A_BYTES_FIELD]))
        except ValueError:
            sys.exit("error: line %d has a non-numeric byte count" % line_num)
    return flow_bytes


def cumulative_bytes(flow_bytes):
    """cumulative[i] holds the bytes carried by the i largest flows."""
    cumulative = [0]
    for size in sorted(flow_bytes, reverse=True):
        cumulative.append(cumulative[-1] + size)
    return cumulative


def top_flow_count(cumulative, flow_percent):
    num_flows = len(cumulative) - 1
    return min(math.ceil(num_flows * flow_percent / PERCENT), num_flows)


def byte_share(cumulative, flow_percent):
    """Percent of all bytes carried by the largest flow_percent percent of flows."""
    return PERCENT * cumulative[top_flow_count(cumulative, flow_percent)] / cumulative[-1]


def print_table(cumulative):
    print("flows %d total_payload_bytes %d" % (len(cumulative) - 1, cumulative[-1]))
    print("top_percent_of_flows percent_of_bytes")
    for flow_percent in TABLE_PERCENTS:
        print("%g %.2f" % (flow_percent, byte_share(cumulative, flow_percent)))


def x_pos(flow_percent):
    inner = WIDTH - MARGIN_LEFT - MARGIN_RIGHT
    fraction = (math.log10(flow_percent) - X_MIN_EXP) / (X_MAX_EXP - X_MIN_EXP)
    return MARGIN_LEFT + fraction * inner


def y_pos(byte_percent):
    inner = HEIGHT - MARGIN_TOP - MARGIN_BOTTOM
    return HEIGHT - MARGIN_BOTTOM - byte_percent / PERCENT * inner


def axes_svg():
    left, right = MARGIN_LEFT, WIDTH - MARGIN_RIGHT
    top, bottom = MARGIN_TOP, HEIGHT - MARGIN_BOTTOM
    parts = []

    # Grid lines and labels for each decade of flows and each 20% of bytes.
    for exp in range(X_MIN_EXP, X_MAX_EXP + 1):
        x = x_pos(10.0 ** exp)
        parts.append("<line x1='%.1f' y1='%d' x2='%.1f' y2='%d' stroke='%s'/>"
                     % (x, top, x, bottom, GRID_COLOR))
        parts.append("<text x='%.1f' y='%d' text-anchor='middle'>%g%%</text>"
                     % (x, bottom + LABEL_GAP, 10.0 ** exp))
    for pct in range(0, int(PERCENT) + 1, Y_STEP):
        y = y_pos(pct)
        parts.append("<line x1='%d' y1='%.1f' x2='%d' y2='%.1f' stroke='%s'/>"
                     % (left, y, right, y, GRID_COLOR))
        parts.append("<text x='%d' y='%.1f' text-anchor='end'>%d%%</text>"
                     % (left - TICK_GAP, y + TICK_GAP / 2, pct))

    parts.append("<rect x='%d' y='%d' width='%d' height='%d' fill='none' stroke='#444'/>"
                 % (left, top, right - left, bottom - top))
    parts.append("<text x='%d' y='%d' text-anchor='middle'>Largest flows, as a percent of "
                 "all flows (log scale)</text>" % ((left + right) / 2, HEIGHT - LABEL_GAP))
    parts.append("<text transform='translate(%d %d) rotate(-90)' text-anchor='middle'>"
                 "Percent of all payload bytes</text>" % (LABEL_GAP, (top + bottom) / 2))
    return parts


def curve_svg(cumulative):
    steps = (X_MAX_EXP - X_MIN_EXP) * POINTS_PER_DECADE
    points = []
    for i in range(steps + 1):
        flow_percent = 10.0 ** (X_MIN_EXP + i / POINTS_PER_DECADE)
        points.append("%.1f,%.1f" % (x_pos(flow_percent),
                                     y_pos(byte_share(cumulative, flow_percent))))
    parts = ["<polyline fill='none' stroke='%s' stroke-width='2.5' points='%s'/>"
             % (CURVE_COLOR, " ".join(points))]

    # Mark one point on the curve and label it below and to the right of the line.
    share = byte_share(cumulative, HIGHLIGHT_PERCENT)
    x, y = x_pos(HIGHLIGHT_PERCENT), y_pos(share)
    parts.append("<circle cx='%.1f' cy='%.1f' r='5' fill='%s'/>" % (x, y, MARK_COLOR))
    parts.append("<text x='%.1f' y='%.1f'>The largest %d flows (%g%%) carry %.1f%% of all "
                 "bytes</text>" % (x + LABEL_GAP, y + 2 * LABEL_GAP,
                                   top_flow_count(cumulative, HIGHLIGHT_PERCENT),
                                   HIGHLIGHT_PERCENT, share))
    return parts


def write_plot(path, cumulative):
    lines = ["<svg xmlns='http://www.w3.org/2000/svg' width='%d' height='%d' "
             "font-family='Helvetica, Arial, sans-serif' font-size='13'>" % (WIDTH, HEIGHT),
             "<rect width='100%' height='100%' fill='white'/>"]
    lines += axes_svg()
    lines += curve_svg(cumulative)
    lines.append("</svg>")
    try:
        with open(path, "w") as out:
            out.write("\n".join(lines) + "\n")
    except OSError as err:
        sys.exit("error: cannot write '%s': %s" % (path, err))


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: ./proj3 -n -r trace_file | python3 %s plot.svg" % sys.argv[0])

    flow_bytes = read_flow_bytes(sys.stdin)
    if not flow_bytes:
        sys.exit("error: no flows in input")
    cumulative = cumulative_bytes(flow_bytes)
    if cumulative[-1] == 0:
        sys.exit("error: flows carry no payload bytes")

    print_table(cumulative)
    write_plot(sys.argv[1], cumulative)


if __name__ == "__main__":
    main()
