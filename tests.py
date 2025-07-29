import pytest
import os
import tempfile
from app import app, db
from models import User, Transaction
from datetime import datetime

@pytest.fixture
def client():
    """Create a test client for the app."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Create a test user
            test_user = User(username='testuser', email='test@example.com')
            test_user.set_password('TestPassword123!')
            test_user.balance = 1000.00
            db.session.add(test_user)
            db.session.commit()
            
            # Create some test transactions
            deposit = Transaction(
                user_id=test_user.id,
                amount=500.00,
                transaction_type='deposit',
                description='Initial deposit',
                timestamp=datetime.utcnow()
            )
            withdrawal = Transaction(
                user_id=test_user.id,
                amount=200.00,
                transaction_type='withdrawal',
                description='Test withdrawal',
                timestamp=datetime.utcnow()
            )
            db.session.add_all([deposit, withdrawal])
            db.session.commit()
            
        yield client
        
        with app.app_context():
            db.session.remove()
            db.drop_all()


def test_index_page(client):
    """Test that the index page loads correctly."""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Welcome to HackFreeBank' in response.data


def test_register_get(client):
    """Test the registration page loads."""
    response = client.get('/register')
    assert response.status_code == 200
    assert b'Create an Account' in response.data


def test_register_post(client):
    """Test user registration works."""
    response = client.post('/register', data={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'NewPassword123!',
        'confirm_password': 'NewPassword123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Your account has been created' in response.data
    
    # Check that the user was created in the database
    with app.app_context():
        user = User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'new@example.com'


def test_login_get(client):
    """Test the login page loads."""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login to Your Account' in response.data


def test_login_success(client):
    """Test successful login."""
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'TestPassword123!',
        'remember': False
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Dashboard' in response.data


def test_login_failure(client):
    """Test login with incorrect credentials."""
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'WrongPassword123!',
        'remember': False
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Login failed' in response.data


def test_logout(client):
    """Test logout functionality."""
    # First log in
    client.post('/login', data={
        'username': 'testuser',
        'password': 'TestPassword123!',
        'remember': False
    })
    
    # Then log out
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b'You have been logged out' in response.data


def test_dashboard_without_login(client):
    """Test that dashboard redirects to login when not authenticated."""
    response = client.get('/dashboard', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login to Your Account' in response.data


def test_dashboard_with_login(client):
    """Test dashboard access when authenticated."""
    client.post('/login', data={
        'username': 'testuser',
        'password': 'TestPassword123!',
        'remember': False
    })
    
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b'$1000.00' in response.data  # Balance check
    assert b'Recent Transactions' in response.data


def test_deposit(client):
    """Test deposit functionality."""
    # First log in
    client.post('/login', data={
        'username': 'testuser',
        'password': 'TestPassword123!',
        'remember': False
    })
    
    # Make a deposit
    response = client.post('/deposit', data={
        'amount': '250.00',
        'description': 'Test deposit'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Deposit of $250.00 successful' in response.data
    
    # Check that balance was updated
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        assert user.balance == 1250.00


def test_withdraw(client):
    """Test withdrawal functionality."""
    # First log in
    client.post('/login', data={
        'username': 'testuser',
        'password': 'TestPassword123!',
        'remember': False
    })
    
    # Make a withdrawal
    response = client.post('/withdraw', data={
        'amount': '150.00',
        'description': 'Test withdrawal'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Withdrawal of $150.00 successful' in response.data
    
    # Check that balance was updated
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        assert user.balance == 850.00


def test_withdraw_insufficient_funds(client):
    """Test withdrawal with insufficient funds."""
    # First log in
    client.post('/login', data={
        'username': 'testuser',
        'password': 'TestPassword123!',
        'remember': False
    })
    
    # Attempt to withdraw more than available balance
    response = client.post('/withdraw', data={
        'amount': '1500.00',
        'description': 'Test withdrawal'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Insufficient funds' in response.data
    
    # Check that balance was not changed
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        assert user.balance == 1000.00 