documentation.pdf: cargo_doc.pdf
	pdflatex documentation.tex

cargo_doc.pdf: ../target/doc pdf_docs
	python cargo_doc.py

pdf_docs:
	mkdir pdf_docs
