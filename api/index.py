# api/index.py

from flask import Flask, render_template

# This part is the same
# New, more robust line
app = Flask(__name__, template_folder='../templates', static_folder='../static')
@app.route('/')
def home():
    """
    This is the main route of our application.
    It renders the index.html file from the 'templates' folder.
    """
    return render_template('index.html')

# --- ADD THIS BLOCK ---
# This block allows you to run the app locally for testing.
# It will only be executed when you run "python api/index.py" directly.
# Vercel will ignore this block because it imports the "app" object directly.
if __name__ == '__main__':
    app.run(debug=True, port=5001)