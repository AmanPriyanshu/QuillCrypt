import streamlit as st
import os, json, uuid, datetime, secrets, hashlib, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Filenames and directories
CONFIG_FILE = "config.json"
POSTS_DB_FILE = "posts_db.json"
POSTS_DIR = "posts"

##########################################
# 1. CONFIGURATION & POSTS DATABASE
##########################################

def get_blog_config():
    """
    Load (or set up) the blog configuration.
    The blog configuration includes the blog's name and a default author.
    """
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
    else:
        st.subheader("Blog Setup")
        blog_name = st.text_input("Enter the Blog Name", placeholder="Literary Musings")
        default_author = st.text_input("Enter the Default Author", placeholder="John Doe")
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
    """Load the posts database (list of post metadata)."""
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
    """Append a new post's metadata to the posts database."""
    posts = load_posts_db()
    posts.append(new_post)
    save_posts_db(posts)

##########################################
# 2. GENERATE INDEX.HTML
##########################################

def generate_index_html(config):
    """
    Generate an index.html file in the root directory.
    It lists all posts (with links to posts/<id>.html).
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
        posts_items += f'<li class="mb-4"><a href="posts/{post_id}.html" class="text-blue-600 hover:underline">{title}</a> <span class="text-gray-600 text-sm">- {date_str} by {author}</span></li>\n'
    index_html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{config['blog_name']} - Home</title>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
  <style>
      @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&display=swap');
      .title-font {{ font-family: 'Playfair Display', serif; }}
      .prose {{ max-width: 65ch; line-height: 1.8; }}
  </style>
</head>
<body class="bg-gray-50">
  <nav class="border-b border-gray-200 bg-white">
      <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div class="flex justify-between h-16">
              <div class="flex">
                  <div class="flex-shrink-0 flex items-center">
                      <h1 class="title-font text-xl text-gray-900">{config['blog_name']}</h1>
                  </div>
              </div>
          </div>
      </div>
  </nav>
  <main class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div class="prose mx-auto">
          <h2 class="text-3xl mb-6">Posts</h2>
          <ul>
            {posts_items}
          </ul>
      </div>
  </main>
</body>
</html>
"""
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(index_html)

##########################################
# 3. SIMPLE ENCRYPTION FUNCTION
##########################################

def encrypt_post(plaintext, password):
    """
    Encrypt the plaintext using AES-CBC.
    This version derives the key directly as SHA-256(password) and uses a random IV.
    Returns a JSON string with:
      - "ct": Base64-encoded ciphertext
      - "iv": IV as hex
    """
    iv = secrets.token_bytes(16)
    key = hashlib.sha256(password.encode()).digest()  # Simplified key derivation
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    encrypted_data = {
         "ct": base64.b64encode(ciphertext).decode('utf-8'),
         "iv": iv.hex()
    }
    return json.dumps(encrypted_data)

##########################################
# 4. GENERATE POST.HTML (INLINE CSS/JS)
##########################################

def generate_post_html(config, post_metadata, encrypted_content, used_password):
    """
    Generate an HTML file for a single post with all CSS and JavaScript inline.
    
    - For a protected post (user-supplied password), a password input is shown.
    - For a public post, an auto-generated password is embedded (via autoDecryptKey)
      so that visitors need only click a button to decrypt.
    """
    post_id     = post_metadata["id"]
    post_title  = post_metadata["title"]
    post_date   = post_metadata["date"]
    post_author = post_metadata["author"]
    is_protected = post_metadata["protected"]

    if is_protected:
        # Do not embed the key; require visitor to type it.
        protection_block = f'''
          <div id="protectedContent" class="mt-8 p-6 bg-gray-100 rounded-lg">
              <p class="text-gray-600 text-center">This content is protected. Enter password to view:</p>
              <div class="flex justify-center mt-4">
                  <input type="password" id="passwordInput" class="border rounded px-4 py-2 mr-2">
                  <button onclick="decryptContent(document.getElementById('passwordInput').value)" class="bg-gray-800 text-white px-4 py-2 rounded hover:bg-gray-700">
                      Unlock
                  </button>
              </div>
          </div>
        '''
        auto_decrypt_script = ""
    else:
        # For public posts, embed the auto-generated key so that decryption works on button-click.
        protection_block = '''
          <div id="publicDecrypt" class="mt-8 text-center">
              <button onclick="decryptContent(autoDecryptKey)" class="bg-gray-800 text-white px-4 py-2 rounded hover:bg-gray-700">
                  Decrypt Post
              </button>
          </div>
        '''
        auto_decrypt_script = f'var autoDecryptKey = "{used_password}";'
    
    post_html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{post_title} - {config['blog_name']}</title>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
  <style>
      @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&display=swap');
      .title-font {{ font-family: 'Playfair Display', serif; }}
      .prose {{ max-width: 65ch; line-height: 1.8; }}
  </style>
</head>
<body class="bg-gray-50">
  <nav class="border-b border-gray-200 bg-white">
      <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div class="flex justify-between h-16">
              <div class="flex">
                  <div class="flex-shrink-0 flex items-center">
                      <h1 class="title-font text-xl text-gray-900">{config['blog_name']}</h1>
                  </div>
              </div>
          </div>
      </div>
  </nav>
  <main class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <article class="prose mx-auto">
          <header class="mb-8">
              <h1 class="title-font text-4xl text-gray-900 mb-4">{post_title}</h1>
              <div class="flex items-center text-gray-600 text-sm">
                  <span>{post_date}</span>
                  <span class="mx-2">·</span>
                  <span>{post_author}</span>
              </div>
          </header>
          <div id="postContent">
              <!-- Decrypted content will appear here -->
          </div>
          <!-- The encrypted data (as JSON) is stored in a hidden textarea -->
          <textarea id="encryptedData" style="display:none;">{encrypted_content}</textarea>
          {protection_block}
      </article>
  </main>
  <!-- Inline JavaScript: Load CryptoJS from CDN and add decryption logic -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
  <script>
      function decryptContent(password) {{
          var encryptedData = JSON.parse(document.getElementById('encryptedData').textContent);
          var iv = CryptoJS.enc.Hex.parse(encryptedData.iv);
          // Derive the key by simply taking SHA-256 of the password
          var key = CryptoJS.SHA256(password);
          var decrypted = CryptoJS.AES.decrypt(
              {{ ciphertext: CryptoJS.enc.Base64.parse(encryptedData.ct) }},
              key,
              {{ iv: iv, padding: CryptoJS.pad.Pkcs7, mode: CryptoJS.mode.CBC }}
          );
          var plaintext = decrypted.toString(CryptoJS.enc.Utf8);
          if (plaintext) {{
              document.getElementById('postContent').innerHTML = plaintext;
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
    # Ensure the posts directory exists
    if not os.path.exists(POSTS_DIR):
        os.makedirs(POSTS_DIR)
    # Write the post HTML to posts/<id>.html
    post_filename = os.path.join(POSTS_DIR, f"{post_id}.html")
    with open(post_filename, "w", encoding="utf-8") as f:
        f.write(post_html)

##########################################
# 5. MAIN STREAMLIT APP
##########################################

def main():
    st.title("Encryption‑Based Blog Creator")
    config = get_blog_config()  # Loads blog name and default author; stops if not configured
    
    st.subheader("Create a New Post")
    post_title   = st.text_input("Post Title")
    post_date    = st.date_input("Post Date", datetime.date.today())
    post_content = st.text_area("Post Content (Markdown or plain text)", height=300)
    # Allow overriding the default author
    post_author  = st.text_input("Author", value=config.get("default_author", ""))
    
    # Checkbox: if checked, the post will be password‑protected.
    protected = st.checkbox("Password protect this post?")
    user_password = ""
    if protected:
        user_password = st.text_input("Enter a password (will not be stored)", type="password")
        st.info("Remember to save your password! It will NOT be stored anywhere.")
    
    if st.button("Publish Post"):
        if post_title.strip() == "" or post_content.strip() == "":
            st.error("Post Title and Content are required.")
            return
        
        # For protected posts the user must supply a password.
        # For public posts, we generate an auto key that will be embedded.
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
        
        # Update posts database and (re)generate index.html.
        update_posts_db(post_metadata)
        generate_index_html(config)
        
        st.success("Post published successfully!")
        st.write(f"Access your post at: **posts/{post_id}.html**")
        st.write("The index page has been updated as **index.html**")
        
if __name__ == "__main__":
    main()
