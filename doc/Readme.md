## The documentation builder

This folder contains scripts and related files for building the documentation
as a PDF. You'll need: `chromium`, `python3` (, `pip`).

Install the dependencies listed in `requirements.txt`. It is recommended to
perform this within a virtual environment. Then just run `make`. This will
produce a file `cargo_doc.pdf` containing the concatenation of all pages. It
will take a while to load all pages in the browser DOM so grab a fresh coffee
or do your favorite other waiting activity (also needs ~2G of memory on my
machine).

```
pip install -r requirements.txt
make
```

## Notes of sanity

The different pages are concatenated within the DOM. Otherwise, small sections
such as pure utility structures would reserve a full page of mostly whitespace.
It would also introduce additional dependencies. This took much longer to
figure out than was appropriate for the cause.
