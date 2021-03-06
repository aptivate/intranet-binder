# extensions to django.core.context_processors

import settings
import binder.main_menu

def additions(request):
    if not hasattr(request, 'session'):
        # probably a fake request for rendering a table
        return {"fake": __file__}

    return {
        'global': {
            'app_title': settings.APP_TITLE,
            'path': request.path,
            'main_menu': binder.main_menu.MainMenu(request),
            'admin_media': settings.ADMIN_MEDIA_PREFIX,
            'user': request.user,
        },
        'root_path': '/admin',
    }
