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
document.querySelectorAll('.like-btn').forEach(button => {
    button.addEventListener('click', function() {
        const tweetId = this.dataset.tweetId;
        fetch(`/like/${tweetId}`, { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                this.querySelector('.like-count').textContent = data.likes;
                this.classList.toggle('active');
            });
    });
});

document.querySelectorAll('.retweet-btn').forEach(button => {
    button.addEventListener('click', function() {
        const tweetId = this.dataset.tweetId;
        fetch(`/retweet/${tweetId}`, { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                this.querySelector('.retweet-count').textContent = data.retweets;
                this.classList.toggle('active');
            });
    });
});