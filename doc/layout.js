(function() {
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
})();
