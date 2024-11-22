if (!!$.prototype.justifiedGallery) {  // if justifiedGallery method is defined
    var options = {
        rowHeight: 140,
        margins: 4,
        lastRow: 'justify'
    };
    $('.article-gallery').justifiedGallery(options);
}

$(document).ready(function () {
    $("#menu-icon").click(function () {
        $('.menu').toggleClass('hidden');
        $('.actions').toggleClass('hidden');
        $("#menu-icon").toggleClass('active');

        if ($('#share').css('visibility') !== 'hidden') {
            $('#share').toggleClass('hidden');
        }
        return false;
    });

    $("#back-top").click(function () {
        window.scrollTo(0, 0);
    })

    /* Toggle between adding and removing the "responsive" class to topnav when the user clicks on the icon */
    $(".header > nav > ul > .icon").click(function () {
        $(".header > nav > ul").toggleClass("responsive");
    });

    $("img.captcha").css('cursor', 'pointer').on('click', function () {
        var $form = $(this).parents('form');

        // Make the AJAX-call
        $.getJSON("/captcha/refresh/", {}, function (json) {

            $form.find('input[name="captcha_0"]').val(json.key);
            $form.find('img.captcha').attr('src', json.image_url);
        });

        return false;
    });
});

function reply_to(id, nickname) {
    $("#id_parent").val(id);
    var content = $("#id_content").val();
    content = '@' + nickname + ' ' + content;
    $("#id_content").val(content);
    $('html, body').animate({
        scrollTop: parseInt($("#reply").offset().top)
    }, 250);
}

function escapeHtml(text) {
    var map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function (m) {
        return map[m];
    });
}