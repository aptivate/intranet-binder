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
    original_function = getattr(target_class_or_module, target_method_name)
    def decorator(before_function):
        def wrapper_with_before(*args, **kwargs):
            before_function(*args, **kwargs)
            return original_function(*args, **kwargs)
        # only now do we have access to the before_function
        setattr(target_class_or_module, target_method_name, wrapper_with_before)
        return wrapper_with_before
    return decorator


def after(target_class_or_module, target_method_name):
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
       
    original_function = getattr(target_class_or_module, target_method_name)
    def decorator(after_function):
        def wrapper_with_after(*args, **kwargs):
            result = original_function(*args, **kwargs)
            after_function(*args, **kwargs)
            return result
        # only now do we have access to the after_function
        setattr(target_class_or_module, target_method_name, wrapper_with_after)
        return wrapper_with_after
    return decorator

from django.utils.functional import curry

def patch(class_or_instance, method_name, replacement_function=None):
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
    """
    
    if replacement_function is None:
        # being used as an (unbound) decorator, so we return a function
        # (the bound decorator) that takes the replacement function as
        # its only argument, and replaces the original with it.
        def bound_decorator(replacement_function):
            patch(class_or_instance, method_name, replacement_function)
            return replacement_function
        return bound_decorator
    else:
        original_function = getattr(class_or_instance, method_name)
        setattr(class_or_instance, method_name, 
            curry(replacement_function, original_function))

def breakpoint(*args, **kwargs):
    import pdb; pdb.set_trace()
        
def modify_return_value(target_class_or_module, target_method_name):
    """
    This decorator generator takes two arguments, a class or module to
    patch, and the name of the method in that class (or function in that
    module) to patch.
    
    It returns a decorator, i.e. a function that can be called with a
    function as its argument (the after_function), and returns a function
    (the wrapper_with_after) that executes the original function/method and
    then the after_function.
    
    You can use this to monkey patch a class or method to execute arbitrary
    code after a method or function returns. Your method is called with one
    additional parameter at the beginning, which is the return value of the
    original function; the value that you return becomes the new return value.
    """
       
    original_function = getattr(target_class_or_module, target_method_name)
    def decorator(after_function):
        def wrapper_with_after(*args, **kwargs):
            result = original_function(*args, **kwargs)
            result = after_function(result, *args, **kwargs)
            return result
        # only now do we have access to the after_function
        setattr(target_class_or_module, target_method_name, wrapper_with_after)
        return wrapper_with_after
    return decorator
