$(document).ready(function () {
    $.ajaxPrefilter(function (options, originalOptions, xhr) {
        var method = (options.type || options.method || 'GET').toUpperCase();
        var tokenMatch = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
        var isSafeMethod = /^(GET|HEAD|OPTIONS|TRACE)$/.test(method);
        if (!options.crossDomain && !isSafeMethod && tokenMatch) {
            xhr.setRequestHeader('X-XSRF-TOKEN', decodeURIComponent(tokenMatch[1]));
        }
    });
});
