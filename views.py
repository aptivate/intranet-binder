# Create your views here.

from django import http
from django.core.urlresolvers import reverse
from django.forms import ModelForm
from django.views.generic.base import TemplateView

class FrontPageView(TemplateView):
    template_name = 'front_page.dhtml'