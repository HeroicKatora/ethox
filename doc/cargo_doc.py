# Based on an example from: https://github.com/HyperionGray/trio-chrome-devtools-protocol/ (Under MIT license)
# Copyright (c) 2018 Hyperion Gray
# Copyright (c) 2018 Andreas Molzer
import base64
import glob
import logging
import os
import os.path
import sys

from cdp import dom, emulation, page, target, runtime
import trio
from trio_cdp import open_cdp_connection

log_level = os.environ.get('LOG_LEVEL', 'info').upper()
logging.basicConfig(level=getattr(logging, log_level))
logger = logging.getLogger('pdf-exporter')
logging.getLogger('trio-websocket').setLevel(logging.WARNING)

async def main():
    ethox_doc = "../target/doc/ethox"

    # Read the code used to layout the page
    async with await trio.open_file('layout.js', 'r') as layout:
        reduction_code = await layout.read()

    async with open_cdp_connection(sys.argv[1]) as conn:
        logger.info('Listing targets')
        targets = await conn.execute(target.get_targets())
        target_id = targets[0].target_id

        logger.info('Attaching to target id=%s', target_id)
        session = await conn.open_session(target_id)

        logger.info('Setting device emulation')
        await session.execute(emulation.set_device_metrics_override(
            width=800, height=600, device_scale_factor=1, mobile=False
        ))

        logger.info('Enabling page events')
        await session.execute(page.enable())

        logger.info('Starting to crawl documentation')

        contents = {}
        for doc_page in glob.iglob(os.path.join(ethox_doc, '**', '*.html'), recursive=True):
            main_contents = await convert_page(session, doc_page, reduction_code)
            contents[doc_page] = main_contents

        await convert_page(session, os.path.join(ethox_doc, 'index.html'), reduction_code)
        root_id = (await session.execute(dom.get_document())).node_id
        body_id = await session.execute(dom.query_selector(root_id, 'body'))
        footer_id = await session.execute(dom.query_selector(root_id, 'footer'))
        main_id = await session.execute(dom.query_selector(root_id, '#main'))

        for (_, contents) in contents.items():
            cloned_id = await session.execute(dom.copy_to(main_id, body_id, footer_id))
            await session.execute(dom.set_outer_html(cloned_id, contents))

        await print_page(session, 'cargo_doc.pdf')

async def convert_page(session, path, reduction_code):
    urlpath = 'file://' + os.path.abspath(path)
    logger.info('Navigating to %s', urlpath)
    async with session.wait_for(page.LoadEventFired):
        await session.execute(page.navigate(url=urlpath))

    (_, exc) = await session.execute(runtime.evaluate(reduction_code))

    root_id = (await session.execute(dom.get_document())).node_id
    main_id = await session.execute(dom.query_selector(root_id, '#main'))
    return await session.execute(dom.get_outer_html(main_id))

async def print_page(session, outpath):
    print_parameters = r"""
    <span class=title>Ethox documentation</span>
    """;

    printer = page.print_to_pdf(header_template=print_parameters)
    (pdf_data, _) = await session.execute(printer)

    async with await trio.open_file(outpath, 'wb') as outfile:
        await outfile.write(base64.b64decode(pdf_data))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.stderr.write('Usage: cargo_doc.py <browser url>')
        sys.exit(1)
    trio.run(main, restrict_keyboard_interrupt_to_checkpoints=True)
