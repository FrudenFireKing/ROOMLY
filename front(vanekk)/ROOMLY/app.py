from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/personal')
def personal():
    return render_template('personal.html')

@app.route('/rooms')
def rooms():
    return render_template('rooms.html')

if __name__ == '__main__':
    app.run(debug=True)