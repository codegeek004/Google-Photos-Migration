import io
from django.shortcuts import render, redirect
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaFileUpload
import requests
import json
from .auth import *
from .utils import *
from django.contrib.auth.decorators import login_required
# Define constants
API_NAME = 'photoslibrary'
API_VERSION = 'v1'

def home(request):
    return render(request, 'home.html')



def get_photos_service(credentials_dict):
    print('get photos service function mai gaya')
    credentials = Credentials(
        token=credentials_dict['token'],
        refresh_token=credentials_dict.get('refresh_token'),
        token_uri=credentials_dict['token_uri'],
        client_id=credentials_dict['client_id'],
        client_secret=credentials_dict['client_secret'],
        scopes=credentials_dict['scopes']
    )
    http = httplib2.Http()
    authorized_http = AuthorizedHttp(credentials, http=http)
    return build(API_NAME, API_VERSION, http=authorized_http, static_discovery=False)

@login_required
def migrate_photos(request):
    print('migrate photos mai gaya')
    print(f"\n\nsession email {request.session.get('destination_credentials')}\n\n")
    print(f"session data {request.session.items()}\n\n")



    if 'source_credentials' not in request.session:
        return redirect('google_auth')

    source_credentials = request.session['source_credentials']
    print('src creds', source_credentials)
    page_token = request.GET.get('page_token')
    photos, next_page_token = get_photos(source_credentials, page_token)

    if request.method == 'POST' and 'action' in request.POST:
        print('post method mai gaya')
        action = request.POST['action']
        print('action', action)
        destination_credentials = request.session.get('destination_credentials')
        print('dest creds', destination_credentials)
        
        # if isinstance(destination_credentials, str) and destination_credentials.strip():
        #     print('inside if isinstance')
        #     destination_credentials = json.loads(destination_credentials)
        # else:
        #     print('inside else of isinstance')
        #     print("Error: destination_credentials is missing or invalid.")
        #     return render(request, 'migrate_photos.html', {
        #         'photos': photos,
        #         'error': 'Destination credentials are missing.'
        #     })

        if action == 'migrate_all':
            print('in migrate all ')
            if destination_credentials:
                print('dest creds mil gaye')
                destination_service = get_photos_service(destination_credentials)
                for photo in photos:
                    file_url = photo['baseUrl'] + "=d"
                    file_name = photo['filename']
                    photo_data = download_photo(file_url)
                    if photo_data:
                        upload_photo(destination_service, photo_data, file_name)
                return render(request, 'migrate_photos.html', {
                    'photos': photos,
                    'success_all': True,
                    'next_page_token': next_page_token
                })

        elif action == 'migrate_selected':
            selected_photo_ids = request.POST.getlist('selected_photos')
            if destination_credentials and selected_photo_ids:
                destination_service = get_photos_service(destination_credentials)
                selected_photos = [photo for photo in photos if photo['id'] in selected_photo_ids]
                for photo in selected_photos:
                    file_url = photo['baseUrl'] + "=d"
                    file_name = photo['filename']
                    photo_data = download_photo(file_url)
                    if photo_data:
                        upload_photo(destination_service, photo_data, file_name)
                return render(request, 'migrate_photos.html', {
                    'photos': photos,
                    'success_selected': True,
                    'next_page_token': next_page_token
                })

    return render(request, 'migrate_photos.html', {
        'photos': photos,
        'next_page_token': next_page_token
    })



def get_photos(credentials_dict, page_token=None):
    service = get_photos_service(credentials_dict)
    results = service.mediaItems().list(pageSize=20, pageToken=page_token).execute()
    items = results.get('mediaItems', [])
    next_page_token = results.get('nextPageToken')
    return items, next_page_token

def download_photo(url):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        return io.BytesIO(response.content)
    except requests.exceptions.RequestException as e:
        print(f"Error downloading photo: {e}")
        return None

def upload_photo(service, photo_data, file_name):
    try:
        media_item = {'newMediaItems': [{'simpleMediaItem': {'fileName': file_name}}]}
        service.mediaItems().batchCreate(body=media_item).execute()
    except Exception as e:
        print(f"Error uploading photo: {e}")

