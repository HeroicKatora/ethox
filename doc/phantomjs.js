"use strict";
/* Renders a cargo-doc web page into a paginatable document.
 *
 * Removes some redundant styles on each page and trait implementation
 * information that does not add any information to readers not also writing
 * code.
 */

var page = require('webpage').create(),
    system = require('system'),
    address, output, size, pageWidth, pageHeight;

if (system.args.length < 3 || system.args.length > 5) {
    console.log('Usage: rasterize.js URL filename [paperwidth*paperheight|paperformat] [zoom]');
    console.log('  paper (pdf output) examples: "5in*7.5in", "10cm*20cm", "A4", "Letter"');
    console.log('  image (png/jpg output) examples: "1920px" entire page, window width 1920px');
    console.log('                                   "800px*600px" window, clipped to 800x600');
    phantom.exit(1);
} else {
    address = system.args[1];
    output = system.args[2];
    page.viewportSize = { width: 600, height: 600 };
    if (system.args.length > 3 && system.args[2].substr(-4) === ".pdf") {
        size = system.args[3].split('*');
        page.paperSize = size.length === 2 ? { width: size[0], height: size[1], margin: '0px' }
                                           : { format: system.args[3], orientation: 'portrait', margin: '1cm' };
    } else if (system.args.length > 3 && system.args[3].substr(-2) === "px") {
        size = system.args[3].split('*');
        if (size.length === 2) {
            pageWidth = parseInt(size[0], 10);
            pageHeight = parseInt(size[1], 10);
            page.viewportSize = { width: pageWidth, height: pageHeight };
            page.clipRect = { top: 0, left: 0, width: pageWidth, height: pageHeight };
        } else {
            console.log("size:", system.args[3]);
            pageWidth = parseInt(system.args[3], 10);
            pageHeight = parseInt(pageWidth * 3/4, 10); // it's as good an assumption as any
            console.log ("pageHeight:", pageHeight);

            page.viewportSize = { width: pageWidth, height: pageHeight };
        }
    }
    if (system.args.length > 4) {
        page.zoomFactor = system.args[4];
    }
    page.open(address, function (status) {
        if (status !== 'success') {
            console.log('Unable to load the address!');
            phantom.exit(1);
        } else {
            page.evaluate(function() {
                // Important: defined here! It captures document on definition.
                function removeElementByClass(cls) {
                    var elements = document.getElementsByClassName(cls);
                    if(elements.length == 0) {
                        return;
                    }
                    elements[0].parentNode.removeChild(elements[0]);
                }

                function removeElementById(id) {
                    var element = document.getElementById(id);
                    if(element === null) {
                        return;
                    }
                    element.parentNode.removeChild(element);
                }

                // From: https://stackoverflow.com/a/15948355
                function click(el){
                    var ev = document.createEvent("MouseEvent");
                    ev.initMouseEvent(
                        "click",
                        true /* bubble */, true /* cancelable */,
                        window, null,
                        0, 0, 0, 0, /* coordinates */
                        false, false, false, false, /* modifier keys */
                        0 /*left*/, null
                    );
                    el.dispatchEvent(ev);
                }

                // Remove a bunch of decoration elements.
                removeElementByClass('sub');
                removeElementByClass('sidebar');
                removeElementByClass('nav');
                removeElementByClass('theme-picker');

                // Remove the implementations list. It doesn't add.
                removeElementById('synthetic-implementations');
                removeElementById('synthetic-implementations-list');
                removeElementById('blanket-implementations');
                removeElementById('blanket-implementations-list');

                // And a few specific impls
                removeElementById('impl-Clone');
                removeElementById('impl-Copy');
                removeElementById('impl-Debug');
                removeElementById('impl-Display');

                // Remove impl list if no more remain
                var impls_list = document.getElementById('implementations-list');
                if(impls_list !== null && impls_list.getElementsByClassName('impl').length == 0) {
                    removeElementById('implementations');
                    removeElementById('implementations-list');
                }

                main = document.getElementById('main');
                if(main !== null) {
                    // Open the main declaration.
                    toggle = main.getElementsByClassName('collapse-toggle')[0];
                    click(toggle);
                }
            });
            window.setTimeout(function () {
                page.render(output);
                phantom.exit();
            }, 200);
        }
    });
}
