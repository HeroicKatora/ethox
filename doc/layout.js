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

	function removeForeignTraitImpls() {
		var all_impls = document.getElementById('implementations-list');
		all_impls.querySelectorAll('h3').forEach((impl) => {
			var name_link = impl.querySelector('code>a');
			if(name_link === null) {
				return;
			}
			var link_target = name_link.href;
			if(link_target === null) {
				return;
			}
			if(link_target.startsWith('file:')) {
				return;
			}
			all_impls.removeChild(impl);
		});
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

	// And foreign trait impls. Don't care about Clone etc.
	removeForeignTraitImpls();

	// Remove impl list if no more remain
	var impls_list = document.getElementById('implementations-list');
	if(impls_list !== null && impls_list.getElementsByClassName('impl').length == 0) {
		removeElementById('implementations');
		removeElementById('implementations-list');
	}

	// Open the description
	document.querySelectorAll('#main>.hidden-by-usual-hider').forEach((hidden) => {
		hidden.classList.remove('hidden-by-usual-hider');
	})
})();
