import curses
import subprocess
import sys
import os


current_folder = None


def center_text(stdscr, text, y):

    h, w = stdscr.getmaxyx()
    x = w // 2 - len(text) // 2

    stdscr.addstr(y, max(0, x), text)


def run_analysis(stdscr):

    global current_folder

    stdscr.clear()

    center_text(stdscr, "Enter Binary Path:", 5)

    curses.echo()
    h, w = stdscr.getmaxyx()

    path = stdscr.getstr(7, w // 2 - 20).decode()

    curses.noecho()

    stdscr.clear()

    center_text(stdscr, "Analyzing...", 10)

    stdscr.refresh()

    subprocess.run([sys.executable, "analyzer.py", path])

    current_folder = path + "_RE"

    stdscr.clear()

    center_text(stdscr, "Analysis Complete", 10)
    center_text(stdscr, "Press any key to continue", 12)

    stdscr.getch()


def view_file(stdscr, filepath):

    if not os.path.exists(filepath):
        return

    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    pos = 0

    while True:

        stdscr.clear()

        h, w = stdscr.getmaxyx()

        for i in range(h - 1):

            if pos + i >= len(lines):
                break

            stdscr.addstr(i, 0, lines[pos + i][: w - 1])

        key = stdscr.getch()

        if key == curses.KEY_DOWN:
            pos = min(pos + 1, len(lines) - 1)

        elif key == curses.KEY_UP:
            pos = max(pos - 1, 0)

        elif key == ord("q"):
            break


def menu(stdscr):

    options = [
        "Analyze Binary",
        "View Strings",
        "View Imports",
        "View Exports",
        "View Disassembly",
        "View Pseudocode",
        "View Callgraph",
        "View Xrefs",
        "Exit",
    ]

    index = 0

    while True:

        stdscr.clear()

        h, w = stdscr.getmaxyx()

        start_y = h // 2 - len(options) // 2

        for i, option in enumerate(options):

            text = f"{i+1}. {option}"

            if i == index:
                text = f"> {text} <"

            center_text(stdscr, text, start_y + i)

        key = stdscr.getch()

        if key == curses.KEY_UP:
            index = (index - 1) % len(options)

        elif key == curses.KEY_DOWN:
            index = (index + 1) % len(options)

        elif key == 10:

            if index == 0:
                run_analysis(stdscr)

            elif index == 8:
                break

            elif current_folder:

                files = [
                    "strings.txt",
                    "imports.txt",
                    "exports.txt",
                    "disassembly.asm",
                    "pseudocode.txt",
                    "callgraph.txt",
                    "xrefs.txt",
                ]

                view_file(stdscr, os.path.join(current_folder, files[index - 1]))


def main(stdscr):

    curses.curs_set(0)
    menu(stdscr)


if __name__ == "__main__":
    curses.wrapper(main)
