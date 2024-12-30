from django.contrib.auth import login
from django.contrib.auth.models import User
from google.oauth2.credentials import Credentials
from google_auth_httplib2 import AuthorizedHttp
import httplib2
from google_auth_oauthlib.flow import Flow
from django.contrib.auth import logout
from django.shortcuts import render, redirect
import requests
CLIENT_SECRETS_FILE = "credentials.json"

def get_google_auth_flow(redirect_uri):
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=[
            'https://www.googleapis.com/auth/photoslibrary.readonly',
            'https://www.googleapis.com/auth/photoslibrary.appendonly',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
            'openid'
        ],
        redirect_uri=redirect_uri
    )
    return flow

def oauth(request):
    return render(request, 'authentication.html')


def google_auth(request):
    flow = get_google_auth_flow('https://127.0.0.1:8000/photos/auth/callback/')
    authorization_url, state = flow.authorization_url()
    return redirect(authorization_url)

def google_auth_callback(request):
    if 'code' not in request.GET:
        return redirect('home')

    flow = get_google_auth_flow('https://127.0.0.1:8000/photos/auth/callback/')
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials
    print('creds in auth callback', credentials)

    # Fetch user info using the token
    userinfo_endpoint = 'https://www.googleapis.com/oauth2/v3/userinfo'
    userinfo_response = requests.get(userinfo_endpoint, headers={
        'Authorization': f'Bearer {credentials.token}'
    })
    
    if userinfo_response.status_code == 200:
        userinfo = userinfo_response.json()
        print('userinfo', userinfo)
        username = userinfo.get('name', 'Unknown User')
        email = userinfo.get('email', 'Unknown Email')
        print('username: ', username)
        print('email: ', email)

        # Save user info or use it
        user, created = User.objects.get_or_create(username=email)
        user.first_name = username
        user.save()

        login(request, user)
    else:
        print("Failed to fetch user info:", userinfo_response.text)

    # Save credentials in session
    request.session['source_credentials'] = credentials_to_dict(credentials)
    return redirect('migrate_photos')


def credentials_to_dict(credentials):
    print('creds to dict function mai gaya')
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }




#################destination auth##########################

def destination_google_auth(request):
    print('destination google auth mai gaya')
    if request.method == 'POST':
        email = request.POST.get('destination_email')
        if not email:
            print("Email is required for destination account authentication.")
            return redirect('home')  # Add error handling logic here

        # **Save destination email for later use**
        request.session['destination_email'] = email

        flow = get_google_auth_flow('https://127.0.0.1:8000/photos/destination/auth/callback/')
        authorization_url, state = flow.authorization_url(access_type='offline')
        return redirect(authorization_url)
    return redirect('home')

    

def destination_google_auth_callback(request):
    print('inside destination google auth callback')
    if 'code' not in request.GET:
        return redirect('home')

    flow = get_google_auth_flow('https://127.0.0.1:8000/photos/destination/auth/callback/')
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials
    print('creds in destination auth callback', credentials)
    dest_creds = credentials_to_dict(credentials)
    request.session['destination_credentials'] = dest_creds
    print(request.session.get('destination_credentials'), 'kjsdbjsbgjsbfsjkdvs')

    # **Fetch and validate destination email**
    destination_email = request.session.get('destination_email', None)
    if not destination_email:
        print("Destination email not found in session.")
        return redirect('home')  # Handle missing email

    # **Fetch user info to confirm token validity**
    userinfo = fetch_user_info(credentials)
    if userinfo and userinfo.get('email') != destination_email:
        print(f"Authenticated email ({userinfo.get('email')}) does not match provided destination email ({destination_email}).")
        return redirect('home')  # Add logic for mismatch handling

    return redirect('migrate_photos')





#####################logout#######################
def logout_view(request):
    source_credentials = request.session.get('source_credentials')
    destination_credentials = request.session.get('destination_credentials')

    if source_credentials:
        requests.post(
            'https://oauth2.googleapis.com/revoke',
            params={'token': source_credentials['token']},
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )

    if destination_credentials:
        requests.post(
            'https://oauth2.googleapis.com/revoke',
            params={'token': destination_credentials['token']},
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )

    request.session.flush()
    logout(request)
    return redirect('home')



####################fetch user creds####################
def fetch_user_info(credentials):
    try:
        response = requests.get(
            'https://www.googleapis.com/oauth2/v1/userinfo',
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching user info: {e}")
        return None