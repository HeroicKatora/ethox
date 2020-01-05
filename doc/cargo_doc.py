# Based on an example from: https://github.com/HyperionGray/trio-chrome-devtools-protocol/ (Under MIT license)
# Copyright (c) 2018 Hyperion Gray
# Copyright (c) 2018 Andreas Molzer
import base64
from contextlib import ExitStack
import glob
import logging
import os
import os.path
import subprocess
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

    (chromium, ws_addr) = await start_chromium()
    logging.debug('Started server at %s', ws_addr)
    with chromium:
        await merge_pages_in(ethox_doc, ws_addr, reduction_code)

async def merge_pages_in(ethox_doc, ws_addr, reduction_code):
    async with open_cdp_connection(ws_addr) as conn:
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
            (target_item, main_contents) = await convert_page(session, doc_page, reduction_code)
            contents[target_item] = main_contents

        await convert_page(session, os.path.join(ethox_doc, 'index.html'), reduction_code)
        root_id = (await session.execute(dom.get_document())).node_id
        body_id = await session.execute(dom.query_selector(root_id, 'body'))
        footer_id = await session.execute(dom.query_selector(root_id, 'footer'))
        main_id = await session.execute(dom.query_selector(root_id, '#main'))

        for (_, contents) in contents.items():
            cloned_id = await session.execute(dom.copy_to(main_id, body_id, footer_id))
            await session.execute(dom.set_outer_html(cloned_id, contents))

        await print_page(session, 'cargo_doc.pdf')

async def start_chromium():
    chromium = ['chromium', '--headless', '--remote-debugging-port=9000']
    with ExitStack() as stack:
        chromium = await trio.open_process(chromium, stderr=subprocess.PIPE)
        stack.callback(chromium.terminate)
        with trio.fail_after(5):
            address = await read_websocket_addr(chromium.stderr)
        running = stack.pop_all()
    return (running, address)

async def read_websocket_addr(stream):
    data = ''
    while True:
        data = data + bytes.decode(await stream.receive_some())
        lines = data.split('\n')
        (lines, data) = (lines[:-1], lines[-1:])
        try:
            line = next(line for line in lines if line.find('ws://') > 0)
        except StopIteration:
            continue
        start = line.index('ws://')
        return line[start:]


async def convert_page(session, path, reduction_code):
    urlpath = 'file://' + os.path.abspath(path)
    logger.info('Navigating to %s', urlpath)
    async with session.wait_for(page.LoadEventFired):
        await session.execute(page.navigate(url=urlpath))

    (_, exc) = await session.execute(runtime.evaluate(reduction_code))

    root_id = (await session.execute(dom.get_document())).node_id
    main_id = await session.execute(dom.query_selector(root_id, '#main'))

    target_item_id = await session.execute(dom.query_selector(main_id, 'h1'))
    target_item = await session.execute(dom.get_outer_html(target_item_id))
    content_html = await session.execute(dom.get_outer_html(main_id))
    return (target_item, content_html) 

async def print_page(session, outpath):
    print_parameters = r"""
    <span class=title>Ethox documentation</span>
    """;

    printer = page.print_to_pdf(header_template=print_parameters)
    (pdf_data, _) = await session.execute(printer)

    async with await trio.open_file(outpath, 'wb') as outfile:
        await outfile.write(base64.b64decode(pdf_data))

if __name__ == '__main__':
    if len(sys.argv) != 1:
        sys.stderr.write('Usage: cargo_doc.py')
        sys.exit(1)
    trio.run(main, restrict_keyboard_interrupt_to_checkpoints=True)
