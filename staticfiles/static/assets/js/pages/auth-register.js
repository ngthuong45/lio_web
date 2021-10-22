(function (window, undefined) {
    'use strict';

    var pageResetForm = $('.auth-register-form');

    // jQuery Validation
    // --------------------------------------------------------------------
    if (pageResetForm.length) {
        pageResetForm.validate({
            onfocusout: function (element) {
              $(element).valid();
            },
            rules: {
                'username': {
                    required: true,
                    minlength: 4
                },
                'email': {
                    required: true,
                    email: true
                },
                'password1': {
                    required: true,
                    minlength: 8
                },
                'password2': {
                    required: true,
                    equalTo: '#id_password1'
                }
            }
        });
    }

})(window);