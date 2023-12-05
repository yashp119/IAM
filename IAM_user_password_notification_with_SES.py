import time
from datetime import datetime, timedelta, timezone
from dateutil import parser
import boto3

iam_client = boto3.client('iam')
ses_client = boto3.client('ses', region_name='us-east-1')  # Replace 'your_ses_region' with your SES region

def send_email(subject, message, recipient_email):
    sender_email = 'yashpareek.amy119@gmail.com'  # Replace with your SES verified email

    ses_client.send_email(
        Source=sender_email,
        Destination={'ToAddresses': [recipient_email]},
        Message={
            'Subject': {'Data': subject},
            'Body': {'Html': {'Data': message}}
        }
    )

def lambda_handler(event, context):
    """ Get IAM creds report, check for expiring passwords & notify users """
    iam_client.generate_credential_report()

    while True:
        # Wait before checking the report status again
        time.sleep(5)

        # Get the credential report generation status
        response = iam_client.get_credential_report()
        if 'Content' in response:
            break

    credential_report = iam_client.get_credential_report()
    credential_report_csv = credential_report['Content'].decode('utf-8')

    # Process the credential report for password expiration
    users_to_notify_password = []
    users_to_notify_access_key = []

    for line in credential_report_csv.split('\n')[1:]:
        fields = line.split(',')
        username = fields[0]
        password_last_changed = fields[5]

        if password_last_changed not in ('N/A', 'not_supported'):
            # Parse the date and time components from the timestamp
            password_last_changed_date = parser.parse(password_last_changed)
            days_since_password_change = (
                datetime.now() - password_last_changed_date.replace(tzinfo=None)).days

            if days_since_password_change > 9:
                # Retrieve user's email address from tags
                response = iam_client.list_user_tags(UserName=username)
                email = None
                for tag in response['Tags']:
                    if tag['Key'] == 'email':
                        email = tag['Value']
                        break
                if email:
                    users_to_notify_password.append({'username': username, 'email': email, 'password_age': days_since_password_change})

    # Process IAM users for access key expiration
    users = iam_client.list_users()

    for user in users['Users']:
        username = user['UserName']

        # Get user's access keys
        access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']

        for access_key in access_keys:
            access_key_id = access_key['AccessKeyId']
            create_date = access_key['CreateDate'].replace(tzinfo=timezone.utc)

            # Calculate access key age
            access_key_age = datetime.now(timezone.utc) - create_date
            max_access_key_age = timedelta(days=3)  # Set your desired access key age limit

            if access_key_age > max_access_key_age:
                # Retrieve user's email address from tags
                response = iam_client.list_user_tags(UserName=username)
                email = None
                for tag in response['Tags']:
                    if tag['Key'] == 'email':
                        email = tag['Value']
                        break
                if email:
                    users_to_notify_access_key.append({'username': username, 'email': email, 'access_key_id': access_key_id, 'access_key_age': access_key_age.days})

    # Send email notifications for password expiration
    for user in users_to_notify_password:
        username = user['username']
        password_age = user['password_age']
        message = f'''
            <html>
            <body>
                <p>Hello {username},</p>
                <p>Your password to access the <a href="https://signin.aws.amazon.com/console">AWS web console</a> has expired or will be expiring within the next 20 days.</p>
                <p>Your current password age is {password_age} days.</p>
                
                
            </body>
            </html>
            '''
        ses_client.send_email(
            Source='yashpareek.amy119@gmail.com',
            Destination={'ToAddresses': [user['email']]},
            Message={
                'Subject': {'Data': 'AWS Password Expiry Notification'},
                'Body': {'Html': {'Data': message}}
            }
        )

    # Send email notifications for access key expiration
    for user in users_to_notify_access_key:
        username = user['username']
        access_key_id = user['access_key_id']
        access_key_age = user['access_key_age']
        message = f'''
            <html>
            <body>
                <p>Hello {username},</p>
                <p>Your access key {access_key_id} is about to expire. Please rotate it as soon as possible.</p>
                <p>Your current access key age is {access_key_age} days.</p>
                
            </body>
            </html>
            '''
        ses_client.send_email(
            Source='yashpareek.amy119@gmail.com',
            Destination={'ToAddresses': [user['email']]},
            Message={
                'Subject': {'Data': 'AWS Access Key Expiry Notification'},
                'Body': {'Html': {'Data': message}}
            }
        )

    return 'Password and access key expiry notifications sent.'
