import markdown
import sys
import os
import subprocess

if len(sys.argv) < 2:
    print("Usage: python md2pdf.py <input.md>")
    sys.exit(1)

md_file = sys.argv[1]
html_file = md_file.replace('.md', '.html')
pdf_file = md_file.replace('.md', '.pdf')

with open(md_file, 'r', encoding='utf-8') as f:
    text = f.read()

html = markdown.markdown(text, extensions=['fenced_code', 'tables'])

# Add some basic styling
full_html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }}
    h1, h2, h3 {{ color: #333; }}
    code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }}
    pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; }}
    th {{ background-color: #f2f2f2; text-align: left; }}
</style>
</head>
<body>
{html}
</body>
</html>
"""

with open(html_file, 'w', encoding='utf-8') as f:
    f.write(full_html)

edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
abs_html = os.path.abspath(html_file)
abs_pdf = os.path.abspath(pdf_file)

cmd = [
    edge_path,
    "--headless",
    "--disable-gpu",
    f"--print-to-pdf={abs_pdf}",
    f"file:///{abs_html}"
]

print(f"Converting {md_file} to PDF via MS Edge...")
subprocess.run(cmd, check=True)
print(f"Success! Generated {pdf_file}")

# Clean up html
os.remove(html_file)
