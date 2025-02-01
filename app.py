import streamlit as st
import os, json, uuid, datetime, secrets, hashlib, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Filenames and directories
CONFIG_FILE = "config.json"
POSTS_DB_FILE = "posts_db.json"
POSTS_DIR = "posts"

##########################################
# 1. BLOG CONFIGURATION & POSTS DATABASE
##########################################

def get_blog_config():
    """
    Load (or create) the blog configuration (blog name and default author).
    """
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
    else:
        st.subheader("Blog Setup")
        blog_name = st.text_input("Enter the Blog Name", placeholder="My Literary Blog")
        default_author = st.text_input("Enter the Default Author", placeholder="Jane Doe")
        if st.button("Save Blog Configuration"):
            if blog_name.strip() == "":
                st.error("Blog name cannot be empty.")
                st.stop()
            config = {"blog_name": blog_name, "default_author": default_author}
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f)
            st.success("Configuration saved! Please reload the app.")
            st.stop()
        else:
            st.stop()
    return config

def load_posts_db():
    """Load the posts database (a list of post metadata)."""
    if os.path.exists(POSTS_DB_FILE):
        with open(POSTS_DB_FILE, "r", encoding="utf-8") as f:
            posts = json.load(f)
    else:
        posts = []
    return posts

def save_posts_db(posts):
    """Save the posts database."""
    with open(POSTS_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(posts, f, indent=2)

def update_posts_db(new_post):
    """Append a new post’s metadata to the posts database."""
    posts = load_posts_db()
    posts.append(new_post)
    save_posts_db(posts)

##########################################
# 2. GENERATE INDEX.HTML WITH CUSTOM CSS
##########################################

def generate_index_html(config):
    """
    Generate an index.html file in the root directory that lists all posts.
    Uses custom inline CSS (no Tailwind).
    """
    posts = load_posts_db()
    posts_items = ""
    # Sort posts by date (most recent first)
    posts_sorted = sorted(posts, key=lambda x: x["date"], reverse=True)
    for post in posts_sorted:
        post_id = post["id"]
        title = post["title"]
        date_str = post["date"]
        author = post["author"]
        posts_items += f'<li><a href="posts/{post_id}.html">{title}</a> <span style="color:#666;font-size:0.9em;">- {date_str} by {author}</span></li>\n'
    index_html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{config['blog_name']} - Home</title>
  <style>
    body {{
      font-family: Georgia, serif;
      background-color: #fff;
      color: #333;
      margin: 0;
      padding: 0;
    }}
    header {{
      background-color: #f5f5f5;
      padding: 20px;
      text-align: center;
    }}
    header h1 {{
      margin: 0;
      font-size: 2.5em;
    }}
    .container {{
      max-width: 800px;
      margin: 20px auto;
      padding: 20px;
    }}
    ul {{
      list-style-type: disc;
      margin-left: 40px;
    }}
    li {{
      margin-bottom: 10px;
    }}
    a {{
      text-decoration: none;
      color: #333;
    }}
    a:hover {{
      color: #555;
    }}
  </style>
</head>
<body>
  <header>
    <h1>{config['blog_name']}</h1>
  </header>
  <div class="container">
    <h2>Posts</h2>
    <ul>
      {posts_items}
    </ul>
  </div>
</body>
</html>
"""
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(index_html)

##########################################
# 3. ENCRYPTION FUNCTION
##########################################

def encrypt_post(plaintext, password):
    """
    Encrypt the plaintext (Markdown content) using AES-CBC.
    The key is derived as SHA-256(password) (for simplicity) and a random IV is used.
    Returns a JSON string containing:
      - "ct": Base64-encoded ciphertext
      - "iv": IV as hex string
    """
    iv = secrets.token_bytes(16)
    key = hashlib.sha256(password.encode()).digest()  # simplified key derivation
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    encrypted_data = {
        "ct": base64.b64encode(ciphertext).decode("utf-8"),
        "iv": iv.hex()
    }
    return json.dumps(encrypted_data)

##########################################
# 4. GENERATE POST.HTML WITH CUSTOM CSS/JS
##########################################

def generate_post_html(config, post_metadata, encrypted_content, used_password):
    """
    Generate an HTML file for a single post.
    Uses custom inline CSS (no Tailwind) designed to render Markdown correctly.
    For protected posts, the visitor must enter a password; for public posts, the auto-generated key is embedded.
    Inline JavaScript loads CryptoJS and markdown‑it (via CDN) to decrypt the content and render it.
    (Note: literal curly braces in the JavaScript are doubled as {{ and }}.)
    """
    post_id     = post_metadata["id"]
    post_title  = post_metadata["title"]
    post_date   = post_metadata["date"]
    post_author = post_metadata["author"]
    is_protected = post_metadata["protected"]

    if is_protected:
        protection_block = f'''
          <div id="protectedContent" style="margin-top:20px; padding:10px; background-color:#f0f0f0; text-align:center;">
              <p style="color:#666;">This content is protected. Enter password to view:</p>
              <input type="password" id="passwordInput" style="padding:8px; font-size:1em; margin-right:10px;">
              <button class="button" onclick="decryptContent(document.getElementById('passwordInput').value)">Unlock</button>
          </div>
        '''
        auto_decrypt_script = ""
    else:
        protection_block = '''
          <div id="publicDecrypt" style="margin-top:20px; text-align:center;">
              <button class="button" onclick="decryptContent(autoDecryptKey)">Decrypt Post</button>
          </div>
        '''
        auto_decrypt_script = f'var autoDecryptKey = "{used_password}";'
    
    post_html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{post_title} - {config['blog_name']}</title>
  <style>
    body {{
      font-family: Georgia, serif;
      background-color: #fff;
      color: #333;
      margin: 0;
      padding: 0;
    }}
    header {{
      background-color: #f5f5f5;
      padding: 20px;
      text-align: center;
    }}
    header h1 {{
      margin: 0;
      font-size: 2.5em;
    }}
    .container {{
      max-width: 800px;
      margin: 20px auto;
      padding: 20px;
    }}
    .post-header {{
      border-bottom: 1px solid #ccc;
      margin-bottom: 20px;
    }}
    .post-header h1 {{
      margin: 0;
      font-size: 2em;
    }}
    .post-header p {{
      color: #666;
      font-size: 0.9em;
    }}
    .content {{
      margin-top: 20px;
    }}
    /* Markdown styling */
    .markdown-content h1 {{
      font-size: 2em;
      margin-bottom: 0.5em;
    }}
    .markdown-content h2 {{
      font-size: 1.8em;
      margin-bottom: 0.5em;
    }}
    .markdown-content h3 {{
      font-size: 1.5em;
      margin-bottom: 0.5em;
    }}
    .markdown-content p {{
      margin-bottom: 1em;
      line-height: 1.6;
    }}
    .markdown-content ul, .markdown-content ol {{
      margin: 1em 0;
      padding-left: 40px;
    }}
    .markdown-content li {{
      margin-bottom: 0.5em;
    }}
    .markdown-content table {{
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 1em;
    }}
    .markdown-content th, .markdown-content td {{
      border: 1px solid #ddd;
      padding: 8px;
      text-align: left;
    }}
    .button {{
      background-color: #333;
      color: #fff;
      border: none;
      padding: 10px 15px;
      font-size: 1em;
      cursor: pointer;
    }}
    .button:hover {{
      background-color: #555;
    }}
  </style>
</head>
<body>
  <header>
    <h1>{config['blog_name']}</h1>
  </header>
  <div class="container">
    <div class="post-header">
      <h1>{post_title}</h1>
      <p>{post_date} &nbsp;&bull;&nbsp; {post_author}</p>
    </div>
    <div class="content" id="postContent">
      <!-- Decrypted & rendered Markdown will appear here -->
    </div>
    <!-- The encrypted data is stored in a hidden textarea -->
    <textarea id="encryptedData" style="display:none;">{encrypted_content}</textarea>
    {protection_block}
  </div>
  <!-- Inline JavaScript: Load CryptoJS and markdown-it from CDNs, then add decryption logic -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/markdown-it/13.0.1/markdown-it.min.js"></script>
  <script>
      // Create a markdown-it instance with options.
      var md = window.markdownit({{ html: true, linkify: true, typographer: true }});
      
      function decryptContent(password) {{
          var encryptedData = JSON.parse(document.getElementById('encryptedData').textContent);
          var iv = CryptoJS.enc.Hex.parse(encryptedData.iv);
          // Derive the key by taking SHA-256 of the password.
          var key = CryptoJS.SHA256(password);
          var decrypted = CryptoJS.AES.decrypt(
              {{ ciphertext: CryptoJS.enc.Base64.parse(encryptedData.ct) }},
              key,
              {{ iv: iv, padding: CryptoJS.pad.Pkcs7, mode: CryptoJS.mode.CBC }}
          );
          var plaintext = decrypted.toString(CryptoJS.enc.Utf8);
          if (plaintext) {{
              var htmlContent = md.render(plaintext);
              document.getElementById('postContent').innerHTML = '<div class="markdown-content">' + htmlContent + '</div>';
              var protDiv = document.getElementById('protectedContent');
              if (protDiv) protDiv.style.display = 'none';
              var pubDiv = document.getElementById('publicDecrypt');
              if (pubDiv) pubDiv.style.display = 'none';
          }} else {{
              alert('Decryption failed. Incorrect password?');
          }}
      }}
      
      {auto_decrypt_script}
  </script>
</body>
</html>
"""
    if not os.path.exists(POSTS_DIR):
        os.makedirs(POSTS_DIR)
    post_filename = os.path.join(POSTS_DIR, f"{post_id}.html")
    with open(post_filename, "w", encoding="utf-8") as f:
        f.write(post_html)

##########################################
# 5. MAIN STREAMLIT APP
##########################################

def main():
    st.title("Custom CSS Encryption‑Based Blog Creator")
    config = get_blog_config()  # Loads blog name and default author; stops if not configured
    
    st.subheader("Create a New Post")
    post_title   = st.text_input("Post Title")
    post_date    = st.date_input("Post Date", datetime.date.today())
    post_content = st.text_area("Post Content (Markdown supported)", height=300)
    # Optionally override default author
    post_author  = st.text_input("Author", value=config.get("default_author", "Anonymous"))
    
    # Option to password-protect this post.
    protected = st.checkbox("Password protect this post?")
    user_password = ""
    if protected:
        user_password = st.text_input("Enter a password (will not be stored)", type="password")
        st.info("Remember to save your password! It will NOT be stored anywhere.")
    
    if st.button("Publish Post"):
        if post_title.strip() == "" or post_content.strip() == "":
            st.error("Post Title and Content are required.")
            return
        
        # For protected posts, use the user-supplied password.
        # For public posts, auto-generate a key that will be embedded.
        if protected:
            if user_password.strip() == "":
                st.error("Please enter a password for this protected post.")
                return
            used_password = user_password
        else:
            used_password = secrets.token_hex(8)
        
        # Encrypt the post content.
        encrypted_content = encrypt_post(post_content, used_password)
        post_id = str(uuid.uuid4())
        post_metadata = {
            "id": post_id,
            "title": post_title,
            "date": post_date.strftime("%B %d, %Y"),
            "author": post_author.strip() if post_author.strip() != "" else config.get("default_author", "Anonymous"),
            "protected": protected
        }
        
        # Generate the post HTML file.
        generate_post_html(config, post_metadata, encrypted_content, used_password)
        
        # Update the posts database and regenerate index.html.
        update_posts_db(post_metadata)
        generate_index_html(config)
        
        st.success("Post published successfully!")
        st.write(f"Access your post at: **posts/{post_id}.html**")
        st.write("The index page has been updated as **index.html**")
        
if __name__ == "__main__":
    main()
