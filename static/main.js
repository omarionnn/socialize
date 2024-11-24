$(document).ready(function() {
    // Like functionality
    $('.like-btn').click(function() {
        const btn = $(this);
        const tweetId = btn.data('tweet-id');
        
        $.ajax({
            url: `/tweet/${tweetId}/like`,
            type: 'POST',
            success: function(response) {
                btn.find('.like-count').text(response.likes);
                btn.toggleClass('active');
            }
        });
    });

    // Retweet functionality
    $('.retweet-btn').click(function() {
        const btn = $(this);
        const tweetId = btn.data('tweet-id');
        
        $.ajax({
            url: `/tweet/${tweetId}/retweet`,
            type: 'POST',
            success: function(response) {
                btn.find('.retweet-count').text(response.retweets);
                btn.toggleClass('active');
            }
        });
    });

    // Character counter for tweet textarea
    $('textarea[name="content"]').on('input', function() {
        const maxLength = 280;
        const currentLength = $(this).val().length;
        const remainingChars = maxLength - currentLength;
        
        if (remainingChars < 0) {
            $(this).val($(this).val().substring(0, maxLength));
        }
    });
});
