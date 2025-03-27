from app import create_app, db

app = create_app()

with app.app_context():
    db.create_all()  # Creates tables if not exist

if __name__ == '__main__':
    app.run(debug=True)
