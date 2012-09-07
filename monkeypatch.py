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

def patch(class_or_instance, method_name, replacement_function):
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
