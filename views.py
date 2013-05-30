from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

class LoginRequiredMixin(object):
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(LoginRequiredMixin, self).dispatch(*args, **kwargs)

from django.views.generic.base import TemplateView

class FrontPageView(TemplateView):
    template_name = 'front_page.dhtml'

def add_plain_view(clazz):
    clazz.plain_view = staticmethod(clazz.as_view())
    return clazz
