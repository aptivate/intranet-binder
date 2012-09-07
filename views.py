from django.views.generic.base import TemplateView

class FrontPageView(TemplateView):
    template_name = 'front_page.dhtml'
