"""Final assembly: cover (page 0, normalized to A4) + body, with metadata."""

from pypdf import PdfReader, PdfWriter

A4_W, A4_H = 595.28, 841.89  # points

OUT = "/home/z/my-project/download/ai_redteaming_paper.pdf"

writer = PdfWriter()
writer.add_metadata({
    "/Title": "Red-Teaming AI Systems in the Agentic Era: A Taxonomy, Evidence "
              "Base, and Statistical Relevance Model",
    "/Author": "Red Agentic Teams Research",
    "/Subject": "AI red teaming research: weakness taxonomy W1-W14, evidence "
                "review, Bayesian relevance model, and module build plan",
    "/Keywords": "AI red teaming, LLM security, agentic AI, OWASP, MITRE ATLAS, "
                 "Bayesian statistics, jailbreaks",
})


def normalize_page_to_a4(page):
    box = page.mediabox
    w, h = float(box.width), float(box.height)
    if abs(w - A4_W) > 0.05 or abs(h - A4_H) > 0.05:
        page.scale_to(A4_W, A4_H)
    return page


writer.add_page(normalize_page_to_a4(PdfReader("cover.pdf").pages[0]))
for page in PdfReader("main.pdf").pages:
    writer.add_page(page)
with open(OUT, "wb") as f:
    writer.write(f)
print("delivered:", OUT, "-", len(writer.pages), "pages")
