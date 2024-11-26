// Set up CSRF token for all AJAX requests
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrfToken);
        }
    }
});

// Character Counter
const tweetContent = document.getElementById('tweetContent');
const charCounter = document.getElementById('charCounter');
const MAX_CHARS = 280;

if (tweetContent) {
    tweetContent.addEventListener('input', function() {
        const remaining = MAX_CHARS - this.value.length;
        charCounter.textContent = `${remaining} characters remaining`;
        
        if (remaining <= 20) {
            charCounter.classList.add('text-danger');
            charCounter.classList.remove('text-warning');
        } else if (remaining <= 50) {
            charCounter.classList.add('text-warning');
            charCounter.classList.remove('text-danger');
        } else {
            charCounter.classList.remove('text-warning', 'text-danger');
        }
    });
}

// Image Preview
function previewImage(input) {
    const preview = document.getElementById('imagePreview');
    const img = preview.querySelector('img');
    
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        
        reader.onload = function(e) {
            img.src = e.target.result;
            preview.classList.remove('d-none');
        }
        
        reader.readAsDataURL(input.files[0]);
    }
}

function removeImage() {
    const preview = document.getElementById('imagePreview');
    const input = document.querySelector('input[type="file"][name="image"]');
    preview.classList.add('d-none');
    preview.querySelector('img').src = '';
    input.value = '';
}

// Share Post
function sharePost(postId) {
    const url = `${window.location.origin}/post/${postId}`;
    navigator.clipboard.writeText(url).then(() => {
        alert('Link copied to clipboard!');
    });
}

// Relative Timestamps
function updateTimestamps() {
    document.querySelectorAll('.post-timestamp').forEach(timestamp => {
        const date = moment(timestamp.dataset.timestamp);
        if (date.isValid()) {
            const now = moment();
            const diffDays = now.diff(date, 'days');
            
            if (diffDays < 1) {
                timestamp.textContent = date.fromNow(); // today: 2 hours ago, 5 minutes ago, etc.
            } else if (diffDays < 7) {
                timestamp.textContent = date.format('dddd [at] h:mm A'); // e.g., "Monday at 3:45 PM"
            } else {
                timestamp.textContent = date.format('MMMM D, YYYY [at] h:mm A'); // e.g., "February 15, 2024 at 3:45 PM"
            }
        }
    });
}

// Update timestamps immediately and then every 30 seconds
updateTimestamps();
setInterval(updateTimestamps, 30000);

// Like and Retweet functionality
document.addEventListener('click', function(e) {
    // Handle likes
    if (e.target.closest('.like-btn')) {
        const button = e.target.closest('.like-btn');
        const tweetId = button.dataset.tweetId;
        const likeCount = button.querySelector('.like-count');
        
        fetch(`/tweet/${tweetId}/like`, { 
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Toggle the liked state
                button.classList.toggle('liked', data.liked);
                if (likeCount) {
                    likeCount.textContent = data.likes_count;
                }
                // Update the icon
                const icon = button.querySelector('i');
                if (icon) {
                    icon.className = data.liked ? 'fas fa-heart text-danger' : 'far fa-heart';
                }
            }
        })
        .catch(error => console.error('Error:', error));
    }
    
    // Handle retweets
    if (e.target.closest('.retweet-btn')) {
        const button = e.target.closest('.retweet-btn');
        const tweetId = button.dataset.tweetId;
        const retweetCount = button.querySelector('.retweet-count');
        
        fetch(`/tweet/${tweetId}/retweet`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Toggle the retweeted state
                button.classList.toggle('retweeted', data.retweeted);
                if (retweetCount) {
                    retweetCount.textContent = data.retweets_count;
                }
                // Update the icon
                const icon = button.querySelector('i');
                if (icon) {
                    icon.className = data.retweeted ? 'fas fa-retweet text-success' : 'fas fa-retweet';
                }
            }
        })
        .catch(error => console.error('Error:', error));
    }
});

async function sendNewMessage() {
    const recipientId = document.getElementById('recipient').value;
    const messageContent = document.getElementById('messageContent').value;

    console.log('Sending message:', { recipientId, messageContent });

    if (!recipientId || !messageContent) {
        alert('Please select a recipient and enter a message');
        return;
    }

    try {
        const response = await fetch('/new_conversation', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                recipient_id: recipientId,
                message: messageContent
            })
        });

        console.log('Response status:', response.status);
        const responseData = await response.json();
        console.log('Response data:', responseData);

        if (response.ok) {
            // Close the modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('newMessageModal'));
            modal.hide();
            // Refresh the conversation list
            window.location.reload();
        } else {
            alert(responseData.error || 'Failed to send message');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to send message. Check console for details.');
    }
}
