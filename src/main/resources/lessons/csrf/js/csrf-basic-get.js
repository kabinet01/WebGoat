$(document).ready(function () {
    // Fetch a fresh per-session anti-CSRF token so the legitimate, same-origin submission
    // of the basic-csrf-get form includes it. A forged/external page cannot read this
    // response (same-origin policy) and so cannot learn the value it needs to supply.
    $.get('csrf/basic-get-flag/token', function (result) {
        $('#basicGetFlagToken').val(result.token);
    });
})
