# Create your views here.

from django import forms, http
from django.core.urlresolvers import reverse
from django.views.generic.base import TemplateView

from models import IntranetUser
from password import PasswordChangeMixin
from admin import AdminImageWidgetWithThumbnail

class FrontPageView(TemplateView):
    template_name = 'front_page.dhtml'

class UserProfileForm(PasswordChangeMixin, forms.ModelForm):
    class Meta:
        model = IntranetUser
        exclude = ('is_staff', 'is_active', 'is_superuser', 'password',
            'groups', 'user_permissions', 'first_name', 'last_name',
            'last_login', 'date_joined', 'date_left')

    password1 = forms.CharField(required=False, label="New password")
    password2 = forms.CharField(required=False, label="Confirm new password")
    notes = IntranetUser._meta.get_field('notes').formfield(
        help_text="""e.g. educational background,  professional experience,
        present job, personal interests, languages spoken etc.""")
    # photo = forms.ImageField(widget=AdminImageWidgetWithThumbnail)
        
class UserProfileView(TemplateView):
    template_name = "user_profile.html"

    def get(self, request):
        context = {
            'profile_form': UserProfileForm(instance=request.user)
            }
        return self.render_to_response(context)

    def post(self, request):
        form = UserProfileForm(request.POST, request.FILES,
            instance=request.user)
        
        if form.is_valid():
            form.save(True)
            return http.HttpResponseRedirect(reverse('front_page'))
        else:
            return self.render_to_response({'profile_form': form})