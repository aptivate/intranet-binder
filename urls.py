from django.conf.urls.defaults import patterns, url

import views
import django.contrib.auth.views

urlpatterns = patterns('',
    url(r'^$', 
        views.FrontPageView.as_view(),
        name='front_page'),
    url(r'^login$', django.contrib.auth.views.login,
        {'template_name': 'admin/login.html'}, 
        name="login"),
    url(r'^logout$', django.contrib.auth.views.logout,
        {'template_name': 'front_page.dhtml'}, 
        name="logout"),
    # http://groups.google.com/group/django-users/browse_thread/thread/2f529966472c479d
    url(r'^admin/js/i18n.js', 'django.views.i18n.javascript_catalog'),
)
