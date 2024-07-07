import smtplib

def send_test_email():
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login('jarzcyber@gmail.com', 'kaf12lujaj10L@')
        
        subject = 'Test Email'
        body = 'This is a test email.'
        message = f'Subject: {subject}\n\n{body}'
        
        server.sendmail('jarzcyber@gmail.com', 'lujajaluvuga@gmail.com', message)
        server.quit()
        print('Email sent successfully')
    except Exception as e:
        print(f'Failed to send email: {e}')

send_test_email()

