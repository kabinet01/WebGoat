$(document).ready(function () {
    // Fetch a fresh per-session anti-CSRF token and stash it in the hidden field so the
    // legitimate, same-origin submission of this form includes it.
    $.get('csrf/feedback/token', function (result) {
        $('#csrfFeedbackToken').val(result.csrfToken);
    });
});

webgoat.customjs.feedback = function() {
    var data = {};
    $('#csrf-feedback').find('input, textarea, select').each(function(i, field) {
        data[field.name] = field.value;
    });
    return JSON.stringify(data);
}
