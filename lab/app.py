from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h1>WebSentinel Security Lab</h1>
    <p>Local application for authorized security testing.</p>

    <h2>XSS Test</h2>
    <form action="/search">
        <input name="q" placeholder="Search">
        <button type="submit">Search</button>
    </form>

    <h2>SQL Injection Test</h2>
    <form action="/user">
        <input name="id" placeholder="User ID">
        <button type="submit">Get User</button>
    </form>

    <h2>Directory Exposure Test</h2>
    <a href="/uploads/">Open uploads directory</a>
    """


@app.route("/search")
def search():
    query = request.args.get("q", "")

    # Intentionally vulnerable for the local lab
    return f"""
    <h2>Search Results</h2>
    <p>You searched for: {query}</p>
    """


@app.route("/user")
def user():
    user_id = request.args.get("id", "")

    # Simulated database error for scanner testing
    if "'" in user_id or '"' in user_id:
        return "Database error: invalid query syntax", 500

    return f"User ID: {user_id}"


@app.route("/uploads/")
def uploads():
    return """
    <h1>Index of /uploads/</h1>
    <ul>
        <li><a href="/uploads/example.txt">example.txt</a></li>
        <li><a href="/uploads/backup.zip">backup.zip</a></li>
    </ul>
    """


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
