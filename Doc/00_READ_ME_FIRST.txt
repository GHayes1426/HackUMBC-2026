===========================================================================
 00  READ ME FIRST
     How to use these documents, and the words you need before starting
===========================================================================

WHO THIS IS FOR
---------------
You do not need to know anything about programming to read these files.
They start from zero and build up. By the end you should understand:

  * what every file in this project does, line by line where it matters
  * how a "front end" (the web page) and a "back end" (the Python
    program) talk to each other
  * enough Python, HTML, CSS and JavaScript to build a small app like
    this one yourself

Read them IN ORDER. Each one assumes you've read the ones before it.


THE READING ORDER
-----------------
  00  READ ME FIRST                       (this file: vocabulary)
  01  How the front end and back end work together   <- most important
  02  Python crash course (using this project's code)
  03  app.py            -- the back-end server, the "front door"
  04  base.py + __init__.py -- the plugin system that runs every check
  05  index.html        -- the page layout (front end, part 1)
  06  dashboard.js      -- the page's buttons and pop-ups (front end, part 2)
  07  style.css         -- the page's colors and layout (front end, part 3)
  08  port_scan.py      -- checking which "doors" on the computer are open
  09  listeners.py, system.py, listening_services.py
                        -- finding out which programs are using the network
  10  port_catalog.py   -- recognizing programs and explaining them
  11  ioc_analyzer.py, signatures.py, log_parser.py, detector.py
                        -- spotting attacks in log files
  12  hardening.py      -- checking the computer's built-in protections
  13  port_control.py   -- actually closing and reopening ports
  14  summary.py        -- turning results into the numbers and charts
  15  Supporting files  -- requirements.txt, .gitignore, git, venv, etc.
  16  Build your own app, step by step


WHAT THIS APP IS, IN ONE PARAGRAPH
----------------------------------
The "Network Security Dashboard" is a program you run on your own
computer. It looks at the computer's network "doors" (ports), the
programs using them, its log files and its security settings. It then
shows a web page in your browser with the results, color-coded:
red = fix this, amber = take a look, blue = in normal use, green = safe,
gray = couldn't check. For risky ports it offers a button that closes
the port using the computer's firewall, and another to reopen it.


THE VOCABULARY YOU NEED
-----------------------
Keep coming back to this list. Every other document uses these words.

PROGRAM / CODE
  A program is a list of instructions for a computer, written in a
  programming language. "Code" is the text of those instructions.
  This project uses four languages:
    Python      -- the back end (the part that does the real work)
    HTML        -- the structure of the web page (headings, lists, buttons)
    CSS         -- the look of the web page (colors, sizes, spacing)
    JavaScript  -- the behavior of the web page (what happens on a click)

FILE AND FOLDER
  Code lives in text files. The ending of the name tells you the
  language: .py = Python, .html = HTML, .css = CSS, .js = JavaScript,
  .txt = plain text, .json = data, .md = formatted notes (Markdown).

FRONT END
  Everything the user SEES and CLICKS: the web page in the browser.
  Here: html/index.html, frontend/style.css, frontend/dashboard.js.

BACK END
  The program running behind the scenes that does the work and hands
  results to the front end. Here: app.py and everything in checks/.

SERVER
  A program that waits for requests and answers them. Think of a
  restaurant kitchen: it sits there until an order (a request) comes in,
  then cooks and sends out a plate (a response). app.py is a server.

BROWSER / CLIENT
  Chrome, Safari, Edge, Firefox. The "customer" who places orders.
  The browser asks the server for a page, then displays what it gets.

REQUEST AND RESPONSE
  A request is a message from the browser: "please give me the page at
  this address". The response is the server's answer: the page itself,
  or some data, or an error.

URL (web address)
  e.g.  http://127.0.0.1:5000/api/scan
        |      |         |    |
        |      |         |    +-- the PATH: which thing you want
        |      |         +------- the PORT: which "door" of the computer
        |      +----------------- the ADDRESS: which computer
        +------------------------ the PROTOCOL: the language they speak (HTTP)

127.0.0.1 / "localhost"
  A special address that always means "this same computer". When you
  open http://127.0.0.1:5000 you are talking to a server running on
  your own machine, not somewhere on the internet.

PORT
  A computer has one address but 65,535 numbered "doors" called ports.
  Each program that wants to receive network connections sits behind
  one door. Web servers often use door 80 or 443; this dashboard uses
  door 5000; Remote Desktop uses 3389. An "open port" = a door where a
  program is listening and will answer. Open doors you don't need are
  a security risk because attackers can knock on them.

FIREWALL
  A security guard that stands in front of the doors and can refuse
  entry, even if a program is listening behind the door.

JSON
  A way of writing data as text so programs can pass it around, e.g.
      {"port": 7000, "blocked": true, "message": "Port 7000 closed."}
  Curly braces hold named values; square brackets hold lists.

FUNCTION
  A named, reusable set of instructions. Like a recipe card: "to make
  pancakes, do steps 1-5". You "call" it by name when you need it.

VARIABLE
  A named box that holds a value.  port = 5000  puts 5000 in a box
  called "port".

LIBRARY / PACKAGE / MODULE
  Code other people wrote that you can reuse. Flask is a library that
  does the hard parts of being a web server. A "module" is one .py file;
  a "package" is a folder of modules (like our checks/ folder).

TERMINAL / COMMAND LINE
  The text window where you type commands like  python app.py  instead
  of clicking. On Mac it's "Terminal", on Windows "PowerShell".

OPERATING SYSTEM (OS)
  macOS, Windows or Linux: the base software that runs the computer.
  Each has different commands for the same job, which is why parts of
  this project have three versions of the same thing.


HOW TO READ THE CODE EXAMPLES
-----------------------------
Code examples are indented and set apart like this:

    port = 5000
    print(port)

Lines starting with # in Python (or // in JavaScript) are COMMENTS:
notes for humans that the computer ignores.

    # This is a comment. The computer skips it.
    port = 5000   # comments can also go at the end of a line

Text between three double quotes """like this""" at the top of a Python
file or function is a "docstring": a longer description for humans.

When a document says  app.py:36  it means "file app.py, line 36". Open
the file in VS Code, press Ctrl+G (on Mac and Windows), and type the
line number to jump there.


A TIP FOR LEARNING
------------------
Keep the real file open next to the document. When the document shows
a piece of code, find it in the real file. Change small things (a
message, a color) and reload the page to see what happens. Breaking
things and fixing them is the fastest way to learn. If it breaks badly,
git can put everything back (see document 15).
