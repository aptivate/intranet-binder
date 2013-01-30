class TemporaryPatcher(object):
    def __init__(self, class_or_instance, method_name, replacement_function):
        self.class_or_instance = class_or_instance
        self.method_name = method_name
        self.original_function = getattr(class_or_instance, method_name)
        self.replacement_function = replacement_function
        
        # Apply the patch immediately, in case we're not being used in
        # as context object at all, but just a plain procedure, in which
        # case __enter__ and __exit__ will never be called.
        setattr(self.class_or_instance, self.method_name, 
            self.replacement_function)
         
    def __enter__(self):
        return None # no context variable

    def __exit__(self, exc_type, exc_val, exc_tb):
        setattr(self.class_or_instance, self.method_name, 
            self.original_function)

def get_decorator_or_context_object(class_or_instance, method_name,
    external_replacement_function=None):
    """
    This is really confusing, but helps reduce code duplication. You have
    been warned: be prepared for head-spinning.
    
    A number of monkeypatch functions do the same thing, so it's abstracted
    out here: they behave differently depending on whether
    bare_replacement_function is None or not. If it is, they are
    being used as a decorator for an outside (external) function. If not,
    they are being used to provide a context object for a "with" statement.
    
    In the first case, they return a no-argument decorator which decorates
    a bare replacement function that is not known yet. In the second case, the
    bare replacement function is already known.
    
    We ourselves are used as a decorator for a wrapper function, which does
    the work of the monkeypatch function. So we return a decorator, which
    consumes this decoratee (the wrapper function), and returns either a
    another decorator (this one for the external_replacement_function)
    or a context object.
    
    The wrapper function receives the undecorated external_replacement_function
    as its first argument, and the original function as its second argument.
    
    THIS method is only ever used as an argumented decorator, so always returns
    a raw decorator that takes only one argument, the function to be decorated.
    """

    original_function = getattr(class_or_instance, method_name)
    
    def raw_decorator(wrapper_function):
        if external_replacement_function is None:
            # The monkeypatch function (not this one) is being used as an
            # unbound decorator. In this case, we don't actually know what
            # external function we're wrapping until the decorator is called,
            # after the monkeypatch function returns it.
            # 
            # So we (raw_decorator) return a function (the bound decorator),
            # which takes the external replacement function as its only
            # argument, and replaces the original with it, permanently.
            #
            # The monkeypatch function returns this bound decorator to its
            # caller, where it's applied to the external replacement function.

            def final_decorator(external_replacement_function):
                # Activate the patch now
                actual_final_replacement = curry(wrapper_function,
                    external_replacement_function, original_function)
                setattr(class_or_instance, method_name, actual_final_replacement)
                # It's not useful to return the same wrapper, because
                # that would replace the external_replacement_function with
                # a decorated version, which would stop it from being used
                # to replace multiple methods. So we return the
                # external_replacement_function as it originally was, leaving
                # it unchanged in its definition.
                return external_replacement_function
           
            return final_decorator
        else:
            # Being used as a context object or procedural call.
            # The monkeypatch function returns this TemporaryPatcher to its
            # caller, where it's used as a context object, or discarded.
            # import pdb; pdb.set_trace()
            return TemporaryPatcher(class_or_instance, method_name,
                curry(wrapper_function, external_replacement_function,
                    original_function))

    return raw_decorator

def before(target_class_or_module, target_method_name):
    """
    This decorator generator takes two arguments, a class or module to
    patch, and the name of the method in that class (or function in that
    module) to patch.
    
    It returns a decorator, i.e. a function that can be called with a
    function as its argument (the before_function), and returns a function
    (the wrapper_with_before) that executes the before_function and then
    the original function/method.
    
    You can use this to monkey patch a class or method to execute arbitrary
    code before a method or function is called; the original method is called
    with the same arguments and its return value is returned for you, so
    you don't have to worry about it.
    """

    # must return a decorator, i.e. a function that takes one arg,
    # which is the before_function, and returns a function (a wrapper)
    # that uses the before_function
    # TODO convert to use get_decorator_or_context_object, like the others.
    original_function = getattr(target_class_or_module, target_method_name)
    def decorator(before_function):
        def wrapper_with_before(*args, **kwargs):
            before_function(*args, **kwargs)
            return original_function(*args, **kwargs)
        # only now do we have access to the before_function
        setattr(target_class_or_module, target_method_name, wrapper_with_before)
        return wrapper_with_before
    return decorator


def after(class_or_instance, method_name, bare_replacement_function=None):
    """
    This decorator generator takes two arguments, a class or module to
    patch, and the name of the method in that class (or function in that
    module) to patch.
    
    It returns a decorator, i.e. a function that can be called with a
    function as its argument (the after_function), and returns a function
    (the wrapper_with_after) that executes the original function/method and
    then the after_function.
    
    You can use this to monkey patch a class or method to execute arbitrary
    code after a method or function returns; the original return value
    is retained for you and you don't have to worry about it.
    """
    
    def wrapper_with_after(external_after_function, original_function,
        *args, **kwargs):
        
        result = original_function(*args, **kwargs)
        external_after_function(*args, **kwargs)
        return result
    return get_decorator_or_context_object(class_or_instance, method_name,
        bare_replacement_function)(wrapper_with_after)

from django.utils.functional import curry

def patch(class_or_instance, method_name, bare_replacement_function=None):
    """
    Replaces one method (or module-level function) with another.
    The replacement does not have the same spec as the method it replaces:
    it is passed one additional argument, the original (replaced)
    function/method, as its first argument. This allows you to easily
    call the replaced method surrounded by extra code.
    
    Example:
    
    Use as a simple function:
    
    def replacement_foo(original_function, bar, baz):
        try:
            return original_function(bar, baz)
        except Exception as e:
            frob(e)
    import my.module.name
    patch(my.module.name, 'foo', replacement_foo)
    
    Use as a decorator:
    
    import my.module.name
    @patch(my.module.name, 'foo')
    def replacement_foo(original_function, bar, baz):
        try:
            return original_function(bar, baz)
        except Exception as e:
            frob(e)
            
    Replacing methods works exactly the same as functions. Note that the
    "self" argument comes second in the replacement:
    
    from my.module.name import MyClass
    @patch(MyClass, 'frob')
    def replacement_frob(original_function, self, bar, baz):
        try:
            return original_function(self, bar, baz) + 1
        except Exception as e:
            frob(e)
            
    The name of the replacement function/method doesn't matter much,
    but it will appear in stack traces, so you may want to use the name
    to describe what your replacement adds to the original, or removes
    from it:
    
    * foo_with_exception_handling
    * bar_without_call_for_last_orders
    
    You can also use the result as a context object:
    
        def frob_with_vitamin_c(original_function, *args, **kwargs):
            kwargs['frobbed'] = True
            return original_function(*args, **kwargs)
        with patch(MyClass, 'frob', frob_with_vitamin_c):
            MyClass().frob('hello')
    
    This will automatically undo the patch when the "with" block exits.
    """

    def wrapper_with_patch(external_patch_function, original_function,
        *args, **kwargs):
        return external_patch_function(original_function, *args, **kwargs)
    return get_decorator_or_context_object(class_or_instance, method_name,
        bare_replacement_function)(wrapper_with_patch)

def breakpoint(*args, **kwargs):
    import pdb; pdb.set_trace()

def modify_return_value(class_or_instance, method_name,
    bare_replacement_function=None):
    """
    This decorator generator takes two required arguments, a class or module
    to patch, and the name of the method in that class (or function in that
    module) to patch.
    
    If the thirsd argument (bare_replacement_function) is None, then it
    returns a decorator, i.e. a function that can be called with a function
    as its argument (the after_function), which returns a function
    (the wrapper_with_after) that executes the original function/method and
    then the after_function.
    
    You can use this to monkey patch a class or method to execute arbitrary
    code after a method or function returns. Your method is called with one
    additional parameter at the beginning, which is the return value of the
    original function; the value that you return becomes the new return value.
    """

    def wrapper_with_modify(external_modify_function, original_function,
        *args, **kwargs):
        result = original_function(*args, **kwargs)
        result = external_modify_function(result, *args, **kwargs)
        return result
    return get_decorator_or_context_object(class_or_instance, method_name,
        bare_replacement_function)(wrapper_with_modify)
