import streamlit as st
import pandas as pd
import requests
import time
import json
from urllib.parse import urlencode, parse_qs, urlparse
import re

# Set page configuration
st.set_page_config(
    page_title="LinkedIn Bulk Message Sender",
    layout="wide"
)

# Initialize session state variables
if 'auth_code' not in st.session_state:
    st.session_state.auth_code = None
if 'access_token' not in st.session_state:
    st.session_state.access_token = None
if 'auth_url' not in st.session_state:
    st.session_state.auth_url = None
if 'auth_state' not in st.session_state:
    st.session_state.auth_state = None
if 'debug_info' not in st.session_state:
    st.session_state.debug_info = {}

# LinkedIn API configuration
LINKEDIN_CLIENT_ID = st.secrets.get("LINKEDIN_CLIENT_ID", "")
LINKEDIN_CLIENT_SECRET = st.secrets.get("LINKEDIN_CLIENT_SECRET", "")
REDIRECT_URI = "https://lslinkedinbulk.streamlit.app/"

# Generate a random state for CSRF protection
def generate_state():
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def get_authorization_url():
    """Generate LinkedIn OAuth 2.0 authorization URL"""
    if not st.session_state.auth_state:
        st.session_state.auth_state = generate_state()
    
    params = {
        "response_type": "code",
        "client_id": LINKEDIN_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": st.session_state.auth_state,
        "scope": "w_member_social w_messages r_liteprofile"
    }
    
    auth_url = f"https://www.linkedin.com/oauth/v2/authorization?{urlencode(params)}"
    return auth_url

def get_access_token(authorization_code):
    """Exchange authorization code for access token"""
    token_url = "https://www.linkedin.com/oauth/v2/accessToken"
    
    data = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": REDIRECT_URI,
        "client_id": LINKEDIN_CLIENT_ID,
        "client_secret": LINKEDIN_CLIENT_SECRET
    }
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        response = requests.post(token_url, data=data, headers=headers, timeout=30)
        st.session_state.debug_info['token_response'] = {
            'status': response.status_code,
            'text': response.text
        }
        
        if response.status_code == 200:
            return response.json().get("access_token")
        else:
            st.error(f"Error getting access token: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        st.error(f"Exception getting access token: {str(e)}")
        return None

def get_profile_urn(access_token):
    """Get the URN of the authenticated user"""
    profile_url = "https://api.linkedin.com/v2/me"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Restli-Protocol-Version": "2.0.0"
    }
    
    try:
        response = requests.get(profile_url, headers=headers, timeout=30)
        st.session_state.debug_info['profile_response'] = {
            'status': response.status_code,
            'text': response.text
        }
        
        if response.status_code == 200:
            return response.json().get("id")
        else:
            st.error(f"Error getting profile URN: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        st.error(f"Exception getting profile URN: {str(e)}")
        return None

def extract_linkedin_id(profile_url):
    """Extract profile ID from LinkedIn URL with better error handling"""
    try:
        # Handle different URL formats
        if 'linkedin.com/in/' not in profile_url:
            raise ValueError("Not a valid LinkedIn profile URL")
            
        # Extract the username part
        pattern = r'linkedin\.com/in/([^/?]+)'
        match = re.search(pattern, profile_url)
        
        if match:
            return match.group(1)
        else:
            raise ValueError("Could not extract profile ID from URL")
    except Exception as e:
        st.error(f"Error extracting LinkedIn ID from {profile_url}: {str(e)}")
        return None

def get_profile_urn_by_public_url(access_token, public_url):
    """Get member URN using their public profile URL"""
    profile_id = extract_linkedin_id(public_url)
    
    if not profile_id:
        return None
    
    # Updated API endpoint - using the newer format
    api_url = f"https://api.linkedin.com/v2/people/(url:https://www.linkedin.com/in/{profile_id})"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Restli-Protocol-Version": "2.0.0"
    }
    
    params = {
        "projection": "(id,firstName,lastName)"
    }
    
    try:
        response = requests.get(api_url, headers=headers, params=params, timeout=30)
        st.session_state.debug_info[f'profile_{profile_id}_response'] = {
            'status': response.status_code,
            'text': response.text
        }
        
        if response.status_code == 200:
            return response.json().get("id")
        else:
            st.warning(f"Could not resolve URN for {public_url}: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        st.error(f"Exception getting URN for {public_url}: {str(e)}")
        return None

def send_message(access_token, recipient_urn, message_text):
    """Send a message to a LinkedIn connection"""
    # Updated API endpoint
    api_url = "https://api.linkedin.com/v2/messages"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Restli-Protocol-Version": "2.0.0",
        "Content-Type": "application/json"
    }
    
    # Updated payload structure
    payload = {
        "recipients": [recipient_urn],
        "subject": "Message from LinkedIn Bulk Sender",
        "body": {
            "text": message_text
        },
        "messageType": "MEMBER_TO_MEMBER"
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        st.session_state.debug_info[f'message_{recipient_urn}_response'] = {
            'status': response.status_code,
            'text': response.text
        }
        
        return response.status_code == 201, response.text
    except Exception as e:
        st.error(f"Exception sending message: {str(e)}")
        return False, str(e)

def main():
    st.title(" LinkedIn Bulk Message Sender")
    st.markdown("Send personalized messages to multiple LinkedIn connections")
    
    # Debug toggle
    debug_mode = st.sidebar.checkbox("Debug Mode", value=False)
    
    # Check if credentials are configured
    if not LINKEDIN_CLIENT_ID or not LINKEDIN_CLIENT_SECRET:
        st.error("""
        LinkedIn API credentials not configured. Please:
        1. Add your LinkedIn Client ID and Client Secret to Streamlit secrets
        2. Update the REDIRECT_URI variable with your app's URL
        """)
        
        if debug_mode:
            st.write("Current Client ID:", LINKEDIN_CLIENT_ID)
            st.write("Current Client Secret:", "****" if LINKEDIN_CLIENT_SECRET else "Not set")
        
        return
    
    # Authentication section
    st.header("Step 1: Authenticate with LinkedIn")
    
    if not st.session_state.access_token:
        if not st.session_state.auth_url:
            st.session_state.auth_url = get_authorization_url()
        
        st.markdown(f"""
        1. [Click here to authenticate with LinkedIn]({st.session_state.auth_url})
        2. After authenticating, you'll be redirected back to this app
        3. Copy the authorization code from the URL and paste it below
        """)
        
        # Check if we have a code in the URL (for redirect back)
        query_params = st.experimental_get_query_params()
        if 'code' in query_params and 'state' in query_params:
            if query_params['state'][0] == st.session_state.auth_state:
                st.session_state.auth_code = query_params['code'][0]
                st.experimental_set_query_params()
        
        auth_code = st.text_input("Paste authorization code here:", value=st.session_state.auth_code or "")
        
        if auth_code:
            st.session_state.auth_code = auth_code
            with st.spinner("Exchanging code for access token..."):
                access_token = get_access_token(auth_code)
                
                if access_token:
                    st.session_state.access_token = access_token
                    st.success(" Successfully authenticated with LinkedIn!")
                else:
                    st.error(" Failed to get access token. Please try again.")
    else:
        st.success(" Already authenticated with LinkedIn!")
        if st.button("Logout"):
            st.session_state.access_token = None
            st.session_state.auth_code = None
            st.session_state.auth_url = None
            st.session_state.auth_state = None
            st.experimental_rerun()
    
    # Only show the rest of the app if authenticated
    if st.session_state.access_token:
        st.header("Step 2: Upload CSV File")
        st.markdown("""
        Your CSV file should have these columns:
        - `profile_url`: LinkedIn profile URL (e.g., https://www.linkedin.com/in/username)
        - `message`: The personalized message to send
        """)
        
        # Download template
        template_data = {
            'profile_url': [
                'https://www.linkedin.com/in/sampleuser1',
                'https://www.linkedin.com/in/sampleuser2'
            ],
            'message': [
                'Hello, I would like to connect with you.',
                'Hi, I enjoyed your recent post about...'
            ]
        }
        template_df = pd.DataFrame(template_data)
        csv = template_df.to_csv(index=False)
        st.download_button(
            label="Download CSV Template",
            data=csv,
            file_name="linkedin_message_template.csv",
            mime="text/csv"
        )
        
        uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
        
        if uploaded_file is not None:
            try:
                df = pd.read_csv(uploaded_file)
                
                # Validate CSV structure
                if 'profile_url' not in df.columns or 'message' not in df.columns:
                    st.error("CSV must contain 'profile_url' and 'message' columns")
                    return
                
                st.success(f"Successfully loaded {len(df)} recipients")
                st.dataframe(df.head())
                
                # Configuration options
                st.header("Step 3: Configure Sending Options")
                col1, col2 = st.columns(2)
                
                with col1:
                    delay = st.slider("Delay between messages (seconds)", 5, 60, 15)
                    max_messages = st.number_input("Maximum messages to send", 1, 100, 10)
                
                with col2:
                    test_mode = st.checkbox("Test mode (don't actually send messages)", value=True)
                    preview_messages = st.checkbox("Preview messages before sending", value=True)
                
                # Message preview
                if preview_messages:
                    st.subheader("Message Preview")
                    preview_idx = st.number_input("Select message to preview", 0, len(df)-1, 0)
                    
                    if 0 <= preview_idx < len(df):
                        st.text_area("Message preview", 
                                    df.iloc[preview_idx]['message'], 
                                    height=150)
                
                # Start sending process
                if st.button("Start Sending Messages", type="primary"):
                    access_token = st.session_state.access_token
                    sender_urn = get_profile_urn(access_token)
                    
                    if not sender_urn:
                        st.error("Could not retrieve your profile information")
                        return
                    
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    results = []
                    
                    for i, (index, row) in enumerate(df.iterrows()):
                        if i >= max_messages:
                            break
                        
                        status_text.text(f"Processing {i+1}/{min(len(df), max_messages)}: {row['profile_url']}")
                        progress_bar.progress((i+1) / min(len(df), max_messages))
                        
                        # Get recipient URN
                        recipient_urn = get_profile_urn_by_public_url(access_token, row['profile_url'])
                        
                        if recipient_urn:
                            if test_mode:
                                success, response = True, "TEST MODE - Message not sent"
                                st.info(f"TEST: Would send to {row['profile_url']}")
                            else:
                                success, response = send_message(
                                    access_token, 
                                    recipient_urn, 
                                    row['message']
                                )
                            
                            results.append({
                                'profile_url': row['profile_url'],
                                'status': 'Success' if success else 'Failed',
                                'response': response
                            })
                            
                            if success:
                                st.success(f" Message sent to {row['profile_url']}")
                            else:
                                st.error(f" Failed to send to {row['profile_url']}: {response}")
                        else:
                            results.append({
                                'profile_url': row['profile_url'],
                                'status': 'Failed',
                                'response': 'Could not resolve profile URN'
                            })
                            st.error(f" Could not resolve URN for {row['profile_url']}")
                        
                        # Delay between messages to respect rate limits
                        if not test_mode:
                            time.sleep(delay)
                    
                    # Show results summary
                    st.header("Sending Results")
                    results_df = pd.DataFrame(results)
                    st.dataframe(results_df)
                    
                    # Calculate success rate
                    success_count = len(results_df[results_df['status'] == 'Success'])
                    total_count = len(results_df)
                    st.metric("Success Rate", f"{success_count}/{total_count} ({success_count/total_count*100:.1f}%)")
                    
                    # Provide download link for results
                    csv = results_df.to_csv(index=False)
                    st.download_button(
                        label="Download Results as CSV",
                        data=csv,
                        file_name="message_sending_results.csv",
                        mime="text/csv"
                    )
                    
            except Exception as e:
                st.error(f"Error processing CSV file: {str(e)}")
    
    # Debug information
    if debug_mode and st.session_state.debug_info:
        st.sidebar.header("Debug Information")
        st.sidebar.json(st.session_state.debug_info)

if __name__ == "__main__":
    main()
