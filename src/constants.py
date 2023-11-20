import os
from langchain import PromptTemplate
import logging

# -----------------------  PATH CONSTANTS -------------------------
FILE_LOCATION = "../data/"
if not os.path.exists(FILE_LOCATION):
    os.makedirs(FILE_LOCATION)

IMAGES_PATH = "../data/image_uploads/"
if not os.path.exists(IMAGES_PATH):
    os.makedirs(IMAGES_PATH)


EMBEDDING_FILE = os.path.join(FILE_LOCATION, "embedding.pkl")

LOGS_DIR = "logs/"
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)
LOGGING_PATH = os.path.join(LOGS_DIR, "interviewLogs.log")


# -----------------------  CODE CONSTANTS -------------------------
DEPLOYMENT = False
TEMPRATURE = 0.1
MAX_TOKEN = 300
EMBEDDING_CHUNK_SIZE = 500

# -----------------------  PROMPTS CONSTANTS -------------------------
INSTRUCTIONS = """[INST]<<SYS>>your name is the {}. act like the person whoes context is below. the context is your professional details, answer the question using the context whoes context is provided below.
                  if the question is not related to professional stuff or context reply 'this is not my domain'
                  """
ORIGINAL_PROMPT = """The answer should be concise and brief """

TEMPLATE = """

do not use "according to context" or "in the context" or "Based on the provided context" or realted to this 
Use the following context (delimited by <ctx></ctx>) to answer the question:
<</SYS>>
------
<ctx>
Context:
{context}
</ctx>

------
Answer the following question
question:
{question}[/INST]
AI:
"""
name = "neil"
inst = INSTRUCTIONS.format(name)
template = inst + ORIGINAL_PROMPT + TEMPLATE
PROMPT = PromptTemplate(
    input_variables=["context", "question"],
    template=template,
)


# ------------------------------ Logging Constants ------------------------------
logging.basicConfig(
    filename=LOGGING_PATH,
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
