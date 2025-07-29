#!/usr/bin/env python3

import os
import click
import getpass
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask
from tabulate import tabulate
from models import db, User, Transaction
from utils.logger import log_transaction, log_security_event

# Load environment variables
load_dotenv()

# Create a minimal Flask app to initialize the database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)


@click.group()
def cli():
    """HackFreeBank Command Line Interface
    
    This CLI allows you to interact with your bank account from the terminal.
    """
    pass


@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--email', prompt=True, help='Your email address')
def register(username, email):
    """Register a new bank account"""
    with app.app_context():
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            click.echo(click.style('Username already exists!', fg='red'))
            return
            
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            click.echo(click.style('Email already registered!', fg='red'))
            return
            
        # Get password (hidden input)
        password = getpass.getpass('Enter password: ')
        confirm_password = getpass.getpass('Confirm password: ')
        
        if password != confirm_password:
            click.echo(click.style('Passwords do not match!', fg='red'))
            return
            
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            log_security_event('USER_REGISTERED_CLI', f'New user registered via CLI: {username}')
            click.echo(click.style(f'Account created successfully!', fg='green'))
        except Exception as e:
            db.session.rollback()
            click.echo(click.style(f'Error creating account: {str(e)}', fg='red'))


@cli.command()
@click.option('--username', prompt=True, help='Your username')
def login(username):
    """Log in to your bank account"""
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        
        if not user:
            click.echo(click.style('User not found!', fg='red'))
            return None
            
        password = getpass.getpass('Enter password: ')
        
        if user.check_password(password):
            if user.totp_enabled:
                token = click.prompt('Enter your 2FA code')
                
                from utils.two_factor import verify_totp
                if not verify_totp(user.totp_secret, token):
                    click.echo(click.style('Invalid 2FA code!', fg='red'))
                    log_security_event('CLI_2FA_FAILED', f'Failed 2FA verification via CLI', user.username)
                    return None
                
                log_security_event('CLI_2FA_SUCCESS', f'Successful 2FA verification via CLI', user.username)
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_security_event('USER_LOGIN_CLI', f'User logged in via CLI', user.username)
            click.echo(click.style(f'Welcome back, {user.username}!', fg='green'))
            return user
        else:
            click.echo(click.style('Invalid password!', fg='red'))
            log_security_event('CLI_LOGIN_FAILED', f'Failed login attempt via CLI for user {username}')
            return None


@cli.command()
@click.option('--username', prompt=True, help='Your username')
def balance(username):
    """Check your account balance"""
    with app.app_context():
        user = login(username)
        if user:
            click.echo(click.style(f'Current balance: ${user.balance:.2f}', fg='blue'))


@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--amount', prompt=True, type=float, help='Amount to deposit')
@click.option('--description', prompt=True, default='CLI Deposit', help='Transaction description')
def deposit(username, amount, description):
    """Deposit money into your account"""
    with app.app_context():
        user = login(username)
        if not user:
            return
            
        if amount <= 0:
            click.echo(click.style('Amount must be positive!', fg='red'))
            return
            
        amount = round(amount, 2)  # Round to 2 decimal places
        
        # Create transaction
        transaction = Transaction(
            user_id=user.id,
            amount=amount,
            transaction_type='deposit',
            description=description
        )
        
        # Update user balance
        user.balance += amount
        
        # Save changes
        db.session.add(transaction)
        db.session.commit()
        
        # Log transaction
        log_transaction(user.username, 'deposit', amount)
        
        click.echo(click.style(f'Successfully deposited ${amount:.2f}', fg='green'))
        click.echo(click.style(f'New balance: ${user.balance:.2f}', fg='blue'))


@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--amount', prompt=True, type=float, help='Amount to withdraw')
@click.option('--description', prompt=True, default='CLI Withdrawal', help='Transaction description')
def withdraw(username, amount, description):
    """Withdraw money from your account"""
    with app.app_context():
        user = login(username)
        if not user:
            return
            
        if amount <= 0:
            click.echo(click.style('Amount must be positive!', fg='red'))
            return
            
        amount = round(amount, 2)  # Round to 2 decimal places
        
        # Check if user has sufficient balance
        if amount > user.balance:
            click.echo(click.style('Insufficient funds!', fg='red'))
            return
            
        # Create transaction
        transaction = Transaction(
            user_id=user.id,
            amount=amount,
            transaction_type='withdrawal',
            description=description
        )
        
        # Update user balance
        user.balance -= amount
        
        # Save changes
        db.session.add(transaction)
        db.session.commit()
        
        # Log transaction
        log_transaction(user.username, 'withdrawal', amount)
        
        click.echo(click.style(f'Successfully withdrew ${amount:.2f}', fg='green'))
        click.echo(click.style(f'New balance: ${user.balance:.2f}', fg='blue'))


@cli.command()
@click.option('--username', prompt=True, help='Your username')
@click.option('--limit', default=10, help='Number of transactions to show')
def history(username, limit):
    """View your transaction history"""
    with app.app_context():
        user = login(username)
        if not user:
            return
            
        transactions = Transaction.query.filter_by(user_id=user.id).order_by(
            Transaction.timestamp.desc()
        ).limit(limit).all()
        
        if not transactions:
            click.echo('No transactions found.')
            return
            
        # Format transactions for display
        table_data = []
        for tx in transactions:
            if tx.transaction_type == 'deposit':
                amount = click.style(f'+${tx.amount:.2f}', fg='green')
            else:
                amount = click.style(f'-${tx.amount:.2f}', fg='red')
                
            table_data.append([
                tx.id,
                tx.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                tx.transaction_type.capitalize(),
                amount,
                tx.description or ''
            ])
            
        headers = ['ID', 'Date', 'Type', 'Amount', 'Description']
        click.echo(tabulate(table_data, headers=headers, tablefmt='fancy_grid'))
        click.echo(click.style(f'Current balance: ${user.balance:.2f}', fg='blue'))


if __name__ == '__main__':
    cli() 