(function (window, undefined) {
    'use strict';

    var pageLoginForm = $('.auth-login-form');

    // jQuery Validation
    // --------------------------------------------------------------------
    if (pageLoginForm.length) {
        pageLoginForm.validate({
            onfocusout: function (element) {
                $(element).valid();
            },
            rules: {
                'login': {
                    required: true,
                    email: true
                },
                'password': {
                    required: true,
                    minlength: 8
                }
            }
        });
    }

})(window);
