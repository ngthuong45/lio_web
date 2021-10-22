(function (window, undefined) {
    'use strict';

    var pageResetPasswordForm = $('.auth-reset-password-form');

    // jQuery Validation
    // --------------------------------------------------------------------
    if (pageResetPasswordForm.length) {
        pageResetPasswordForm.validate({
            onfocusout: function (element) {
                $(element).valid();
            },
            rules: {
                'oldpassword': {
                    minlength: 8
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