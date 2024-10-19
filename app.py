from flask import Flask, render_template, request
import requests
import os

app = Flask(__name__)

# VirusTotal API and URL
url = 'https://www.virustotal.com/vtapi/v2/file/scan'
api_key = open("vt-api.txt","r").read().strip()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get the uploaded file
        uploaded_file = request.files['file']
        if uploaded_file.filename == '':
            return "No file selected"
        
        # Save the uploaded file temporarily
        file_path = os.path.join('uploads', uploaded_file.filename)
        uploaded_file.save(file_path)

        params = {"apikey": api_key}
        with open(file_path, "rb") as file:
            # Make the POST request to upload the file
            response = requests.post(url, files={"file": file}, params=params)
            response_json = response.json()

            # Error handling for response
            if 'sha1' not in response_json:
                return "Error: Could not fetch file report."
        
            file_url = f"https://www.virustotal.com/api/v3/files/{response_json['sha1']}"

            # Request the file report
            headers = {"accept": "application/json", "x-apikey": api_key}
            response = requests.get(file_url, headers=headers)

            # Check if the response is successful
            if response.status_code != 200:
                return f"Error: Failed to get report, status code {response.status_code}"

            report = response.json()

            # Extract relevant data from report
            attributes = report.get("data", {}).get("attributes", {})
            analysis_details = {
                "name": attributes.get("meaningful_name", "unable to fetch"),
                "size": attributes.get("size", 0) * 10**-3,
                "description": attributes.get("type_description", "N/A"),
                "hash": attributes.get("sha256", "N/A"),
                "results": [],
                "summary": "",
            }

            # Loop through analysis results
            for key, values in attributes.get("last_analysis_results", {}).items():
                verdict = values['category']
                analysis_details["results"].append({'name': key, 'verdict': verdict})

            # Summary based on malicious count
            malicious_count = sum(1 for result in analysis_details["results"] if result['verdict'] == 'malicious')
            analysis_details['summary'] = (
                f"{malicious_count} antivirus found the given file malicious !!"
                if malicious_count != 0 else "No antivirus found the file malicious"
            )

            return render_template('result.html', analysis_details=analysis_details)

    return render_template('index.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
