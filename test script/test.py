import requests
import threading
import random

# Define the API endpoint URL
api_url = 'http://localhost:6000'

# Function to create a new conversation session
def create_new_conversation(question):
    data = {'question': question}
    response = requests.post(f'{api_url}/conversation', data=data)
    response_data = response.json().get('data', {})
    answer = response_data.get('response')
    return answer

# Function to simulate a user chatting with AI
def simulate_user( messages):
    ai_response =create_new_conversation(messages)
    print('------------------------')
    print(f'question: {messages}')
    print(f'AI responds: {ai_response}')
    print('------------------------')

# Define the list of users and their chat messages
message=["tell me about wajiha?","what is wajiha's qualification?", "what is wajiha's intrests", "Do wajiha have any publication? ", "is wajiha is good fit for madchine learning position?"]



# users = []
# for i in range(1, 10):
#     user = {
#         'user_id': f'u{i}',
#         'messages': message
#     }
#     users.append(user)

# # Create threads for each user
# threads = []
# for user in users:
#     user_id = user['user_id']
#     m=random.choice(message)
#     thread = threading.Thread(target=simulate_user, args=(m,))
#     threads.append(thread)

# # Start the threads
# for thread in threads:
#     thread.start()

# # Wait for all threads to finish
# for thread in threads:
#     thread.join()

simulate_user(message[0])

# print("All users have finished chatting.")
