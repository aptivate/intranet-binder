from collections import namedtuple

Generator = namedtuple('Generator', ('url_name', 'title'))
Item = namedtuple('Item', ('href', 'title'))

class Menu:
    def __init__(self):
        self.generators = []
    
    def __getitem__(self, key):
        # g = self.generators[key]
        # return Item(reverse(g.link_name), g.title)
        return self.generators[key]
    
    def append(self, title, url_name):
        self.generators.append(Generator(url_name, title))
        
    def replace(self, title, url_name):
        for i, g in enumerate(self.generators):
            if g.title == title:
                self.generators[i] = Generator(url_name, title)

class MainMenu(Menu):
    def __init__(self, request):
        Menu.__init__(self)
        self.append("Home", 'front_page')
        
        if request.user.is_authenticated():
            self.append("Documents", 'document_list')
        
            if request.user.is_manager:
                from .configurable import UserModel
                user_changelist = ('admin:%s_%s_changelist' %
                    (UserModel._meta.app_label, UserModel._meta.module_name))
                from django.utils.text import capfirst
                self.append(capfirst(UserModel._meta.verbose_name_plural),
                    user_changelist)
                self.append("Admin", 'admin:index')
