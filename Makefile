#
# apt-get install pandoc wkhtmltopdf
#
SOURCE_FILES = $(shell find . -type f -name "*.md")
PDF_FILES = $(patsubst %.md,%.pdf,$(SOURCE_FILES))
HTML_FILES = $(patsubst %.md,%.html,$(SOURCE_FILES))
EPUB_FILES = $(patsubst %.md,%.epub,$(SOURCE_FILES))
ODT_FILES = $(patsubst %.md,%.odt,$(SOURCE_FILES))

TARGET_FILES = $(PDF_FILES) $(HTML_FILES) $(EPUB_FILES) $(ODT_FILES)

all: base.css $(TARGET_FILES)

clean:
	rm -f $(TARGET_FILES)

%.css: %.sass
	sass $< $@

%.pdf: %.md pdf.css
	pandoc -V papersize:a4 --self-contained --pdf-engine wkhtmltopdf --css pdf.css -f markdown -t pdf -o $@ $<

%.html: %.md html.css
	pandoc --css html.css --standalone -f markdown -t html -o $@ $<

%.epub: %.md
	pandoc -f markdown -t epub -o $@ $<

%.odt: %.md
	pandoc -f markdown -t opendocument -o $@ $<

