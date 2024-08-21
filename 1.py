import requests
import json
import os
import base64
import concurrent.futures

def curlPost(url, data):
        headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json; charset=UTF-8',
        'Origin': 'https://ebank.mbbank.com.vn',
        'Referer': 'https://ebank.mbbank.com.vn/cp/pl/login?logout=1',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
        'X-Request-Id': '2024062116262750',
        'biz-platform': 'biz-1.0',
        'biz-tracking': '/cp/pl/login/1',
        'biz-version': '1.1.31942.1616',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }

        response = requests.post(url, headers=headers, data=json.dumps(data))
        result = response.json()
        return result
def generate_captcha():
    url = "https://ebank.mbbank.com.vn/corp/common/generateCaptcha"
    payload = {
        'deviceId': "1",
        'refNo': "1"
    }
    response = curlPost(url,data=payload)
    if 'encryptedCaptcha' in response:
        base64_captcha_img = response['imageBase64']
        return (base64_captcha_img)
    else:
        return {"status": False, "msg": "Error generate_captcha"}
def save_image_from_base64(base64_img, index, output_folder):
    # Remove the header "data:image/png;base64," if present
    base64_img = base64_img.split(',', 1)[-1]

    # Decode base64 to bytes
    img_data = base64.b64decode(base64_img)

    # Define the output file path
    file_path = os.path.join(output_folder, f'image_{index}.png')

    # Write the image data to a file
    with open(file_path, 'wb') as f:
        f.write(img_data)

    print(f'Saved image {index}')

# Main function to generate and save 1000 captcha images using concurrent futures
def main():
    output_folder = 'mbbank_biz_captcha'
    
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)
    
    # Number of images to fetch and save
    num_images = 2000
    
    # Use ThreadPoolExecutor for concurrent execution
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for i in range(num_images):
            future = executor.submit(generate_captcha)
            futures.append(future)
        
        for index, future in enumerate(concurrent.futures.as_completed(futures)):
            base64_image = future.result()
            save_image_from_base64(base64_image, index, output_folder)

if __name__ == "__main__":
    main()