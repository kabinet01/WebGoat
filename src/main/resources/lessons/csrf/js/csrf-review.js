$(document).ready(function () {
//    $("#postReview").on("click", function () {
//        var commentInput = $("#reviewInput").val();
//        $.ajax({
//            type: 'POST',
//            url: 'csrf/review',
//            data: JSON.stringify({text: commentInput}),
//            contentType: "application/json",
//            dataType: 'json'
//        }).then(
//            function () {
//                getChallenges();
//                $("#commentInput").val('');
//            }
//        )
//    });

    var html = '<li class="comment">' +
        '<div class="pull-left">' +
        '<img class="avatar" src="images/avatar1.png" alt="avatar"/>' +
        '</div>' +
        '<div class="comment-body">' +
        '<div class="comment-heading">' +
        '<h4 class="user">USER / STARS stars</h4>' +
        '<h5 class="time">DATETIME</h5>' +
        '</div>' +
        '<p>COMMENT</p>' +
        '</div>' +
        '</li>';

    getChallenges();

    function getChallenges() {
        $("#list").empty();
        $.get('csrf/review', function (result, status, jqXHR) {
            // The server hands out a fresh per-session anti-CSRF token on every load of
            // this page via the X-CSRF-Token response header; the review form must echo
            // it back on submit or the POST will be rejected.
            $("#validateReq").val(jqXHR.getResponseHeader('X-CSRF-Token'));
            for (var i = 0; i < result.length; i++) {
                var comment = html.replace('USER', result[i].user);
                comment = comment.replace('DATETIME', result[i].dateTime);
                comment = comment.replace('COMMENT', result[i].text);
                comment = comment.replace('STARS', result[i].stars)
                $("#list").append(comment);
            }

        });
    }
})
