# Intranet Binder Application

This is the application that "binds" the Intranet together. Other
Intranet modules may only depend on this application. It contains the
main menu, a default theme, and adds a global variable for use in templates.

## Installation

Check out or unpack the source code into a directory called `binder` inside
your Django project. So you should have `binder/urls.py`, etc.

Import the Binder URLs from `binder/urls.py` into your project-wide `urls.py`,
or copy and change them:

	import binder.urls
	...
	urlpatterns = patterns('',
	    url(r'', include(binder.urls)),
		...

Edit your `settings.py` and add `binder` to `INSTALLED_APPS`.

Edit your `settings.py` and add the following lines, or if you already
have a `TEMPLATE_CONTEXT_PROCESSORS` setting, add
`binder.context.intranet_global` to it. This adds the `global` object
to your templates.

	TEMPLATE_CONTEXT_PROCESSORS = \
	    list(global_settings.TEMPLATE_CONTEXT_PROCESSORS) + \
	    [
	        'binder.context.additions',
	        'search.context.additions',
	    ]

If you want to switch your user class from User to IntranetUser, add the
following line to `settings.py`:

	AUTHENTICATION_BACKENDS = ('binder.auth.IntranetUserBackend',)
