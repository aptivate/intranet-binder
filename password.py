from django import forms

class PasswordChangeMixin(object):
    COMPLETE_BOTH = 'You must complete both password boxes to set or ' + \
        'change the password'
    MISMATCH = 'Please enter the same password in both boxes.'
        
    def clean(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        
        from django.core.exceptions import ValidationError
        
        if password2 and not password1:
            raise ValidationError({'password1': [self.COMPLETE_BOTH]})

        if password1 and not password2:
            raise ValidationError({'password2': [self.COMPLETE_BOTH]})
        
        if password1 and password2:
            if password1 != password2:
                raise ValidationError({'password2': [self.MISMATCH]})
        
        return super(PasswordChangeMixin, self).clean()

    def _post_clean(self):
        super(PasswordChangeMixin, self)._post_clean()

        # because password is excluded from the form, it's not updated
        # in the model instance, so it's never changed unless we poke it
        # in here.
        
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2:
            if password1 == password2:
                self.instance.set_password(password1)
